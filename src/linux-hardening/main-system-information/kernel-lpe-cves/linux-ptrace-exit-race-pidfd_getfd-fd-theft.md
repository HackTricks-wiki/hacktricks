# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

एक उपयोगी **Linux kernel privesc pattern** है **ptrace authorization bug** को privileged process से **file descriptor theft** में बदलना।

Qualys के `__ptrace_may_access()` case study (CVE-2026-46333) में attacker ऐसे **privileged process से race करता है जो exit हो रहा हो या credentials drop कर रहा हो** और attacker process में FD duplicate करने के लिए `pidfd_getfd()` का उपयोग करता है।<sup>[[1]](#references)[[2]](#references)</sup>

## मुख्य विचार

`pidfd_getfd()` किसी अन्य process से file descriptor को duplicate करता है, लेकिन पहले target के विरुद्ध ptrace-style permissions की जाँच करता है।<sup>[[3]](#references)</sup> यदि **teardown window** के दौरान वह authorization गलत तरीके से grant हो जाए, तो unprivileged attacker इन चीज़ों को copy कर सकता है:

- privileged helper द्वारा पहले से खोली गई **sensitive files** के FDs
- root के रूप में पहले से authorized **authenticated IPC channels** के FDs

इससे kernel-side authorization bug एक बहुत व्यावहारिक userspace primitive में बदल जाता है।<sup>[[1]](#references)</sup>

## यह primitive खतरनाक क्यों है

इस attack के लिए privileged helper में किसी bug की आवश्यकता **नहीं** होती। Helper को केवल कुछ मूल्यवान चीज़ अस्थायी रूप से hold करनी होती है:

- `/etc/shadow`
- `/etc/ssh/*_key`
- एक privileged D-Bus / systemd connection
- कोई अन्य पहले से खुला secret या authorized channel

एक बार attacker process में duplicate हो जाने के बाद, duplicate उसी open file description को refer करता है। इसलिए बाद के reads या IPC requests मूल pathname को फिर से खोलने या नया authentication flow शुरू करने के बजाय पहले से खुले FD का उपयोग करते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. ऐसे **setuid / setgid / file-capability binary** या **root daemon** की पहचान करें जो sensitive files खोलता हो या उपयोगी IPC connections बनाए रखता हो।<sup>[[2]](#references)</sup>
2. ऐसा relationship हासिल करें जो target path के लिए relevant ptrace policy checks को satisfy करता हो (उदाहरण के लिए, permissive YAMA settings के अंतर्गत spawned privileged child का **parent** होना)।<sup>[[2]](#references)[[4]](#references)</sup>
3. Process के **exiting**, **dropping credentials**, या ऐसी स्थिति में प्रवेश करते समय race करें, जहाँ ptrace access उपलब्ध नहीं रहना चाहिए था।<sup>[[2]](#references)</sup>
4. संकीर्ण authorization window के दौरान target FD को duplicate करने के लिए `pidfd_open()` + `pidfd_getfd()` का उपयोग करें।<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Unprivileged context से stolen FD का पुनः उपयोग करें।<sup>[[2]](#references)</sup>
- privileged file descriptor से secrets `read()` करें
- stolen authenticated IPC channel पर requests भेजकर **root-side actions** प्राप्त करें

Minimal primitive shape।<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## ऑडिट करने के लिए Practical targets

ऐसे binaries और daemons को प्राथमिकता दें जो, भले ही थोड़े समय के लिए, इनमें से कोई काम करते हों:<sup>[[1]](#references)[[2]](#references)</sup>

- privilege transitions पूरी करने से पहले केवल root द्वारा खोली जा सकने वाली files खोलना
- **system bus** से connect करना और पहले से authorized channel बनाए रखना
- helper boundaries के पार privileged FDs भेजना
- `do_exit()`-adjacent teardown के दौरान security-sensitive काम करना

अच्छे hunting candidates:<sup>[[1]](#references)</sup>

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- root desktop daemons जो D-Bus methods expose करते हैं

## YAMA as an exploit gate

`kernel.yama.ptrace_scope` ptrace-family abuse के लिए एक major practical gate है:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: classical same-UID ptrace behavior
- `1`: आम तौर पर parent -> child tracing की अनुमति देता है, जिससे कुछ public exploit paths reachable रह सकते हैं
- `2`: attach-style access के लिए `CAP_SYS_PTRACE` आवश्यक है और इस path में unprivileged `pidfd_getfd()` abuse को block करता है
- `3`: reboot होने तक ptrace attach को पूरी तरह disable करता है

इस technique के लिए, `ptrace_scope=2` एक strong **temporary mitigation** है, क्योंकि यह unprivileged users के लिए public `pidfd_getfd()` exploitation path को `-EPERM` के साथ तोड़ देता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review ideas

Privileged Linux software का audit करते समय इन combinations को देखें:

- **privileged child process** + **attacker-controlled parent**।<sup>[[2]](#references)[[4]](#references)</sup>
- **valuable open files** तक temporary access
- **authenticated D-Bus/systemd channels** तक temporary access।<sup>[[2]](#references)</sup>
- classic `ptrace(2)` के बाहर **ptrace-style authorization** का reuse करने वाले security decisions
- ऐसे kernel APIs जो मौजूदा privileged FDs को **duplicate, inherit, या re-export** कर सकते हैं

Kernel का audit करते समय, **task teardown** के दौरान **ptrace-equivalent authorization** करने वाले किसी भी path को high risk मानें, खासकर यदि success से `task->files` या अन्य पहले से authorized process resources तक direct access मिलता हो।<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Linux Kernel के ptrace Path में Local Root Privilege Escalation और Credential Disclosure (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
