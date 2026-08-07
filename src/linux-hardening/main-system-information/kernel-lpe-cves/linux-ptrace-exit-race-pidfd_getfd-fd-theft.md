# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

एक उपयोगी **Linux kernel privesc pattern** है किसी **ptrace authorization bug** को privileged process से **file descriptor theft** में बदलना।

Qualys के `__ptrace_may_access()` case study (CVE-2026-46333) में attacker एक **privileged process जो exit कर रहा हो या credentials drop कर रहा हो** के साथ race करता है और attacker process में FD duplicate करने के लिए `pidfd_getfd()` का उपयोग करता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` किसी दूसरे process से file descriptor duplicate करता है, लेकिन पहले target के विरुद्ध ptrace-style permissions check करता है। यदि किसी **teardown window** के दौरान वह authorization गलत तरीके से grant हो जाए, तो एक unprivileged attacker ये copy कर सकता है:

- किसी privileged helper द्वारा पहले से खोली गई **sensitive files** के FDs
- root के रूप में पहले से authorized **authenticated IPC channels** के FDs

इससे kernel-side authorization bug एक बहुत practical userspace primitive में बदल जाता है।<sup>[[1]](#references)</sup>

## यह primitive खतरनाक क्यों है

इस attack के लिए privileged helper में किसी bug की आवश्यकता **नहीं** होती। Helper को केवल अस्थायी रूप से कोई valuable चीज़ hold करनी होती है:

- `/etc/shadow`
- `/etc/ssh/*_key`
- कोई privileged D-Bus / systemd connection
- कोई अन्य पहले से खुला secret या authorized channel

एक बार attacker process में duplicate हो जाने के बाद, kernel operations को original pathname या किसी fresh authentication flow पर नहीं, बल्कि **stolen FD** पर enforce करता है।<sup>[[1]](#references)</sup>

## Exploitation pattern

1. किसी **setuid / setgid / file-capability binary** या **root daemon** की पहचान करें, जो sensitive files खोलता हो या useful IPC connections बनाए रखता हो।
2. ऐसा relationship प्राप्त करें जो target path के लिए relevant ptrace policy checks को satisfy करे (उदाहरण के लिए, permissive YAMA settings के अंतर्गत spawned privileged child का **parent** होना)।
3. Process के **exiting**, **dropping credentials**, या ऐसी स्थिति में प्रवेश करते समय race करें, जहाँ ptrace access unavailable हो जाना चाहिए था।
4. Narrow authorization window के दौरान target FD duplicate करने के लिए `pidfd_open()` + `pidfd_getfd()` का उपयोग करें।
5. Unprivileged context से stolen FD का reuse करें:
- privileged file descriptor से secrets के लिए `read()` करें
- **root-side actions** प्राप्त करने के लिए stolen authenticated IPC channel पर requests भेजें<sup>[[1]](#references)</sup>

Minimal primitive shape:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Audit करने के लिए Practical targets

उन binaries और daemons को प्राथमिकता दें, जो थोड़े समय के लिए भी इनमें से कोई कार्य करते हैं:<sup>[[1]](#references)</sup>

- privilege transitions पूरी होने से पहले केवल root द्वारा खोली जा सकने वाली files खोलना
- **system bus** से connect करना और पहले से authorized channel बनाए रखना
- helper boundaries के पार privileged FDs भेजना
- `do_exit()`-adjacent teardown के दौरान security-sensitive कार्य करना

अच्छे hunting candidates:<sup>[[1]](#references)</sup>

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- root desktop daemons जो D-Bus methods expose करते हैं

## Exploit gate के रूप में YAMA

`kernel.yama.ptrace_scope` ptrace-family abuse के लिए एक प्रमुख practical gate है:<sup>[[4]](#references)</sup>

- `0`: classical same-UID ptrace behavior
- `1`: आम तौर पर parent -> child tracing की अनुमति देता है, जिससे कुछ public exploit paths reachable रह सकते हैं
- `2`: attach-style access के लिए `CAP_SYS_PTRACE` आवश्यक है और इस path में unprivileged `pidfd_getfd()` abuse को block करता है
- `3`: reboot होने तक ptrace attach को पूरी तरह disable करता है

इस technique के लिए, `ptrace_scope=2` एक मजबूत **temporary mitigation** है, क्योंकि यह unprivileged users के लिए public `pidfd_getfd()` exploitation path को `-EPERM` से तोड़ देता है।<sup>[[1]](#references)</sup>

## Detection / review ideas

Privileged Linux software का audit करते समय इन combinations को देखें:

- **privileged child process** + **attacker-controlled parent**
- **valuable open files** तक temporary access
- **authenticated D-Bus/systemd channels** तक temporary access
- ऐसे security decisions जो classic `ptrace(2)` के बाहर ptrace-style authorization का reuse करते हैं
- ऐसे kernel APIs जो मौजूदा privileged FDs को **duplicate, inherit, या re-export** कर सकते हैं

Kernel का audit करते समय, ऐसे किसी भी path को high risk मानें जो **task teardown** के दौरान **ptrace-equivalent authorization** करता है, विशेष रूप से तब जब success से `task->files` या अन्य पहले से authorized process resources तक direct access मिलता हो।

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
