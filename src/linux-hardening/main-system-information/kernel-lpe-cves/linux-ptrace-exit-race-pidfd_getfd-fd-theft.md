# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

एक उपयोगी **Linux kernel privesc pattern** एक **ptrace authorization bug** को privileged process से **file descriptor theft** में बदलना है।

Qualys के `__ptrace_may_access()` case study (CVE-2026-46333) में, attacker एक **privileged process जो exit कर रहा हो या credentials drop कर रहा हो** उसके साथ race करता है और `pidfd_getfd()` का उपयोग करके एक FD को attacker process में duplicate करता है।

## Core idea

`pidfd_getfd()` किसी दूसरे process से file descriptor को duplicate करता है, लेकिन पहले target के विरुद्ध ptrace-style permissions की जाँच करता है। यदि **teardown window** के दौरान वह authorization गलत तरीके से grant हो जाए, तो एक unprivileged attacker ये copy कर सकता है:

- पहले से privileged helper द्वारा खोली गई **sensitive files** के FDs
- root के रूप में पहले से authorized **authenticated IPC channels** के FDs

इससे kernel-side authorization bug एक बहुत practical userspace primitive में बदल जाता है।

## Why the primitive is dangerous

इस attack को स्वयं privileged helper में किसी bug की आवश्यकता **नहीं** होती। Helper को केवल कुछ मूल्यवान चीज़ को अस्थायी रूप से hold करना होता है:

- `/etc/shadow`
- `/etc/ssh/*_key`
- एक privileged D-Bus / systemd connection
- कोई अन्य पहले से खुला secret या authorized channel

Attacker process में duplicate होने के बाद, kernel operations को original pathname या किसी fresh authentication flow पर नहीं, बल्कि **stolen FD** पर लागू करता है।

## Exploitation pattern

1. ऐसे **setuid / setgid / file-capability binary** या **root daemon** को identify करें जो sensitive files खोलता हो या उपयोगी IPC connections बनाए रखता हो।
2. ऐसा relationship प्राप्त करें जो target path के लिए relevant ptrace policy checks को satisfy करता हो (उदाहरण के लिए, permissive YAMA settings के अंतर्गत spawned privileged child का **parent** होना)।
3. Process के **exiting**, **dropping credentials**, या ऐसी किसी state में प्रवेश करने के दौरान race करें, जहाँ ptrace access अनुपलब्ध हो जाना चाहिए था।
4. Narrow authorization window के दौरान target FD को duplicate करने के लिए `pidfd_open()` + `pidfd_getfd()` का उपयोग करें।
5. Unprivileged context से stolen FD का reuse करें:
- privileged file descriptor से secrets पढ़ने के लिए `read()` करें
- **root-side actions** प्राप्त करने के लिए stolen authenticated IPC channel पर requests भेजें

Minimal primitive shape:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## ऑडिट करने के लिए व्यावहारिक targets

उन binaries और daemons को प्राथमिकता दें, जो थोड़े समय के लिए भी इनमें से कोई काम करते हों:

- privilege transitions पूरी करने से पहले root-only files खोलना
- **system bus** से connect करना और पहले से authorized channel बनाए रखना
- helper boundaries के पार privileged FDs भेजना
- `do_exit()`-adjacent teardown के दौरान security-sensitive काम करना

अच्छे hunting candidates:

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- ऐसे root desktop daemons जो D-Bus methods expose करते हैं

## exploit gate के रूप में YAMA

`kernel.yama.ptrace_scope` ptrace-family abuse के लिए एक major practical gate है:

- `0`: classical same-UID ptrace behavior
- `1`: आम तौर पर parent -> child tracing की अनुमति देता है, जिससे कुछ public exploit paths reachable रह सकते हैं
- `2`: attach-style access के लिए `CAP_SYS_PTRACE` आवश्यक है और इस path में unprivileged `pidfd_getfd()` abuse को रोकता है
- `3`: reboot होने तक ptrace attach को पूरी तरह disable करता है

इस technique के लिए, `ptrace_scope=2` एक मजबूत **temporary mitigation** है, क्योंकि यह unprivileged users के लिए public `pidfd_getfd()` exploitation path को `-EPERM` से तोड़ देता है।

## Detection / review ideas

Privileged Linux software का audit करते समय इन combinations को देखें:

- **privileged child process** + **attacker-controlled parent**
- **valuable open files** तक temporary access
- **authenticated D-Bus/systemd channels** तक temporary access
- classic `ptrace(2)` के बाहर **ptrace-style authorization** का reuse करने वाले security decisions
- ऐसे kernel APIs जो मौजूदा privileged FDs को **duplicate, inherit, या re-export** कर सकते हैं

Kernel का audit करते समय, **task teardown** के दौरान **ptrace-equivalent authorization** करने वाले किसी भी path को high risk मानें, खासकर तब जब success से `task->files` या अन्य पहले से authorized process resources तक direct access मिलता हो।

## References

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
