# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

유용한 **Linux kernel privesc pattern**은 **ptrace authorization bug**를 **privileged process**에서 **file descriptor theft**로 전환하는 것입니다.

Qualys의 `__ptrace_may_access()` case study(CVE-2026-46333)에서는 공격자가 **exiting 또는 credentials를 drop하는 privileged process**와 race condition을 일으킨 후 `pidfd_getfd()`를 사용해 FD를 공격자 process로 duplicate합니다.

## 핵심 아이디어

`pidfd_getfd()`는 다른 process의 file descriptor를 duplicate하지만, 먼저 target에 대해 ptrace-style permissions를 확인합니다. 이 authorization이 **teardown window** 중 잘못 granted되면, unprivileged attacker는 다음 항목을 복사할 수 있습니다.

- privileged helper가 이미 연 **sensitive files**의 FD
- 이미 root 권한으로 authorized된 **authenticated IPC channels**의 FD

이를 통해 kernel-side authorization bug가 매우 실용적인 userspace primitive로 전환됩니다.

## 이 primitive가 위험한 이유

이 attack에는 privileged helper 자체의 bug가 필요하지 않습니다. helper가 다음과 같은 유용한 대상을 일시적으로 보유하기만 하면 됩니다.

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- 이미 열려 있는 기타 secret 또는 authorized channel

공격자 process로 duplicate된 후에는 kernel이 original pathname이나 새로운 authentication flow가 아니라 **stolen FD**에 대한 operation을 enforce합니다.

## Exploitation pattern

1. sensitive files를 열거나 유용한 IPC connections를 유지하는 **setuid / setgid / file-capability binary** 또는 **root daemon**을 식별합니다.
2. target path에 대한 관련 ptrace policy checks를 충족하는 relationship을 확보합니다(예: permissive YAMA settings에서 생성된 privileged child의 **parent**가 되는 방법).
3. process가 **exiting**, **credentials를 dropping**하거나, 그 외 ptrace access가 unavailable 상태가 되어야 하는 시점에 race condition을 일으킵니다.
4. `pidfd_open()` + `pidfd_getfd()`를 사용해 좁은 authorization window 동안 target FD를 duplicate합니다.
5. unprivileged context에서 stolen FD를 재사용합니다.
- privileged file descriptor에서 `read()`로 secrets를 읽습니다.
- stolen authenticated IPC channel을 통해 requests를 전송하여 **root-side actions**를 실행합니다.

Minimal primitive shape:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 감사할 실제 대상

잠시라도 다음 중 하나를 수행하는 바이너리와 daemon을 우선적으로 확인하세요.

- 권한 전환을 완료하기 전에 root 전용 파일을 여는 경우
- **system bus**에 연결하고 이미 인증된 channel을 유지하는 경우
- helper 경계를 넘어 권한 있는 FD를 전달하는 경우
- `do_exit()`에 인접한 teardown 중 보안에 민감한 작업을 수행하는 경우

다음은 유망한 hunting 대상입니다.

- password / account management helper
- SSH helper
- PolicyKit / D-Bus mediated helper
- D-Bus method를 노출하는 root desktop daemon

## exploit gate로서의 YAMA

`kernel.yama.ptrace_scope`는 ptrace 계열 abuse를 제한하는 주요 실질적 gate입니다.

- `0`: 고전적인 동일 UID ptrace 동작
- `1`: 일반적으로 parent -> child tracing을 허용하며, 일부 public exploit path를 계속 사용할 수 있음
- `2`: attach 방식 access에 `CAP_SYS_PTRACE`가 필요하며, 이 path에서 권한 없는 사용자의 `pidfd_getfd()` abuse를 차단함
- `3`: reboot할 때까지 ptrace attach를 완전히 비활성화함

이 technique에서 `ptrace_scope=2`는 강력한 **temporary mitigation**입니다. 권한 없는 사용자에 대해 `-EPERM`을 반환하여 public `pidfd_getfd()` exploitation path를 차단하기 때문입니다.

## Detection / review 아이디어

권한 있는 Linux software를 audit할 때 다음 조합을 확인하세요.

- **privileged child process** + **attacker-controlled parent**
- **valuable open files**에 대한 temporary access
- **authenticated D-Bus/systemd channels**에 대한 temporary access
- 기존의 classic `ptrace(2)` 외부에서 **ptrace-style authorization**을 재사용하는 security decision
- 기존의 권한 있는 FD를 **duplicate, inherit, 또는 re-export**할 수 있는 kernel API

kernel을 audit할 때는 **task teardown** 중 **ptrace-equivalent authorization**을 수행하는 모든 path를 high risk로 간주하세요. 특히 성공 시 `task->files` 또는 이미 인증된 기타 process resource에 직접 access할 수 있는 경우 더욱 그렇습니다.

## References

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
