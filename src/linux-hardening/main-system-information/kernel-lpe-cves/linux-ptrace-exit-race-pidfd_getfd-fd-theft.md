# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

유용한 **Linux kernel privesc pattern**은 **ptrace authorization bug**를 **privileged process**에서 **file descriptor theft**로 전환하는 것입니다.

Qualys의 `__ptrace_may_access()` case study (CVE-2026-46333)에서는 공격자가 **exiting 중이거나 credentials를 삭제하는 privileged process**와 race를 수행하고, `pidfd_getfd()`를 사용해 FD를 공격자 process로 복제합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## 핵심 아이디어

`pidfd_getfd()`는 다른 process의 file descriptor를 복제하지만, 먼저 target에 대해 ptrace-style permissions를 확인합니다.<sup>[[3]](#references)</sup> 이 authorization이 **teardown window** 중 잘못 부여되면, unprivileged attacker는 다음을 복사할 수 있습니다.

- privileged helper가 이미 연 **sensitive files**의 FD
- 이미 root 권한으로 authorization된 **authenticated IPC channels**의 FD

이를 통해 kernel-side authorization bug가 매우 실용적인 userspace primitive로 전환됩니다.<sup>[[1]](#references)</sup>

## 이 primitive가 위험한 이유

이 attack에는 privileged helper 자체의 bug가 필요하지 않습니다. helper가 일시적으로 다음과 같은 가치 있는 대상을 보유하기만 하면 됩니다.

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- 이미 열려 있는 기타 secret 또는 authorized channel

공격자 process로 복제된 duplicate는 동일한 open file description을 참조합니다. 따라서 이후의 read 또는 IPC request는 원래 pathname을 다시 열거나 새로운 authentication flow를 시작하는 대신, 이미 열려 있는 FD를 사용합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. sensitive files를 열거나 유용한 IPC connections를 유지하는 **setuid / setgid / file-capability binary** 또는 **root daemon**을 식별합니다.<sup>[[2]](#references)</sup>
2. target path에 적용되는 관련 ptrace policy checks를 충족하는 relationship을 확보합니다. (예: permissive YAMA settings에서 생성된 privileged child의 **parent**가 되는 방법)<sup>[[2]](#references)[[4]](#references)</sup>
3. process가 **exiting**, **dropping credentials** 중이거나, ptrace access가 더 이상 허용되지 않아야 하는 상태로 진입하는 동안 race를 수행합니다.<sup>[[2]](#references)</sup>
4. `pidfd_open()` + `pidfd_getfd()`를 사용해 좁은 authorization window 동안 target FD를 복제합니다.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. unprivileged context에서 stolen FD를 재사용합니다.<sup>[[2]](#references)</sup>
- privileged file descriptor에서 `read()`로 secrets를 읽습니다.
- stolen authenticated IPC channel을 통해 request를 전송하여 **root-side actions**를 수행하게 합니다.

Minimal primitive shape.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 실무적으로 감사할 대상

짧은 시간이라도 다음 중 하나를 수행하는 바이너리와 daemon을 우선적으로 확인하세요:<sup>[[1]](#references)[[2]](#references)</sup>

- privilege transition을 완료하기 전에 root 전용 파일을 open
- **system bus**에 연결하고 이미 인증된 channel을 유지
- helper 경계를 넘어 privileged FD를 전달
- `do_exit()`에 인접한 teardown 중 security-sensitive 작업 수행

우선적으로 살펴볼 만한 대상:<sup>[[1]](#references)</sup>

- password / account management helper
- SSH helper
- PolicyKit / D-Bus mediated helper
- D-Bus method를 노출하는 root desktop daemon

## YAMA를 exploit gate로 사용

`kernel.yama.ptrace_scope`는 ptrace 계열 abuse를 제한하는 주요 실무적 gate입니다:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: 고전적인 same-UID ptrace 동작
- `1`: 일반적으로 parent -> child tracing을 허용하며, 일부 public exploit 경로를 계속 사용할 수 있음
- `2`: attach 방식 access에 `CAP_SYS_PTRACE`가 필요하며 이 경로에서 unprivileged `pidfd_getfd()` abuse를 차단
- `3`: reboot할 때까지 ptrace attach를 완전히 비활성화

이 technique에서는 `ptrace_scope=2`가 강력한 **temporary mitigation**입니다. unprivileged user에 대해 public `pidfd_getfd()` exploitation 경로가 `-EPERM`으로 실패하기 때문입니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review 아이디어

privileged Linux software를 감사할 때 다음 조합을 찾아보세요.

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- **valuable open file**에 대한 temporary access
- **authenticated D-Bus/systemd channel**에 대한 temporary access.<sup>[[2]](#references)</sup>
- 고전적인 `ptrace(2)` 외부에서 **ptrace-style authorization**을 재사용하는 security decision
- 기존 privileged FD를 **duplicate, inherit, or re-export**할 수 있는 kernel API

kernel을 감사할 때는 **task teardown** 중 **ptrace-equivalent authorization**을 수행하는 모든 경로를 high risk로 간주하세요. 특히 성공 시 `task->files` 또는 이미 authorization된 다른 process resource에 직접 access할 수 있는 경우 더욱 그렇습니다.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Linux Kernel ptrace Path의 Local Root Privilege Escalation 및 Credential Disclosure (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
