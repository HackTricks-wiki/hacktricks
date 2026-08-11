# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

有用な **Linux kernel privesc pattern** は、**ptrace authorization bug** を利用して、特権プロセスから **file descriptor theft** を行うことです。

Qualys の `__ptrace_may_access()` case study（CVE-2026-46333）では、攻撃者は **exiting または credentials を drop している privileged process** と race し、`pidfd_getfd()` を使って FD を攻撃者のプロセスへ複製します。<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` は別のプロセスから file descriptor を複製しますが、その前に対象プロセスに対する ptrace-style permissions を確認します。<sup>[[3]](#references)</sup> **teardown window** 中にその authorization が誤って許可されると、unprivileged attacker は次のものをコピーできます。

- privileged helper がすでに開いている **sensitive files** の FD
- root としてすでに authorization された **authenticated IPC channels** の FD

これにより、kernel-side authorization bug が非常に実用的な userspace primitive に変わります。<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

この attack では、privileged helper 自体に bug は必要ありません。helper が価値のあるものを一時的に保持していれば十分です。

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- その他、すでに開かれている secret または authorized channel

攻撃者のプロセスに複製されると、その duplicate は同じ open file description を参照します。そのため、その後の read や IPC request は、元の pathname を再度開いたり、新しい authentication flow を開始したりせず、すでに開かれている FD を使用します。<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. sensitive files を開く、または有用な IPC connections を保持する **setuid / setgid / file-capability binary** または **root daemon** を特定します。<sup>[[2]](#references)</sup>
2. 対象への relevant ptrace policy checks を満たす relationship を確立します（たとえば、permissive YAMA settings 下で spawn された privileged child の **parent** になります）。<sup>[[2]](#references)[[4]](#references)</sup>
3. プロセスが **exiting**、**credentials を dropping**、または ptrace access が利用できなくなるべき状態へ移行している間に race します。<sup>[[2]](#references)</sup>
4. `pidfd_open()` + `pidfd_getfd()` を使用して、狭い authorization window の間に target FD を複製します。<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. unprivileged context から stolen FD を再利用します。<sup>[[2]](#references)</sup>
- privileged file descriptor から secrets を `read()` する
- stolen authenticated IPC channel 経由で requests を送信し、**root-side actions** を実行させる

Minimal primitive shape。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 監査対象として実用的な候補

短時間でも、以下のいずれかを行うバイナリや daemon を優先します:<sup>[[1]](#references)[[2]](#references)</sup>

- 権限移行を完了する前に root 専用ファイルを開く
- **system bus** に接続し、認証済みの channel を保持する
- helper の境界を越えて privileged FD を渡す
- `do_exit()` に隣接する teardown 中に security-sensitive な処理を行う

有力な調査候補:<sup>[[1]](#references)</sup>

- password / account management helper
- SSH helper
- PolicyKit / D-Bus mediated helper
- D-Bus method を公開する root desktop daemon

## YAMA as an exploit gate

`kernel.yama.ptrace_scope` は ptrace-family abuse に対する主要な実用上の gate です:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: 従来の same-UID ptrace behavior
- `1`: 通常、parent -> child tracing を許可するため、一部の public exploit path を到達可能な状態に保てる
- `2`: attach-style access に `CAP_SYS_PTRACE` が必要となり、この path における unprivileged `pidfd_getfd()` abuse をブロックする
- `3`: reboot まで ptrace attach を完全に無効化する

この technique では、`ptrace_scope=2` は強力な **temporary mitigation** です。unprivileged user に対する public `pidfd_getfd()` exploitation path を `-EPERM` で破壊するためです。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review ideas

privileged Linux software を監査する際は、以下の組み合わせを探します:

- **privileged child process** + **attacker-controlled parent**。<sup>[[2]](#references)[[4]](#references)</sup>
- **valuable open files** への一時的な access
- **authenticated D-Bus/systemd channels** への一時的な access。<sup>[[2]](#references)</sup>
- classic `ptrace(2)` の外部で **ptrace-style authorization** を再利用する security decision
- 既存の privileged FD を **duplicate、inherit、または re-export** できる kernel API

kernel を監査する際は、**task teardown** 中に **ptrace-equivalent authorization** を行う path を high risk とみなします。特に、成功時に `task->files` またはその他の既に認証済みの process resource へ直接 access できる場合は注意が必要です。<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Linux Kernel の ptrace Path における Local Root Privilege Escalation と Credential Disclosure (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
