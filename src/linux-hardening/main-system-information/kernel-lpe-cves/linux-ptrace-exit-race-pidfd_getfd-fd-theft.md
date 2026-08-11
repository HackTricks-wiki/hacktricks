# Linux ptrace exit-race `pidfd_getfd()` FD theft

有用な **Linux kernel privesc pattern** は、**ptrace authorization bug** を **privileged process** からの **file descriptor theft** に変えることです。

Qualys の `__ptrace_may_access()` case study（CVE-2026-46333）では、攻撃者は **exiting または credentials を削除中の privileged process** と race を行い、`pidfd_getfd()` を使って FD を攻撃者の process に duplicate します。<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` は別の process から file descriptor を duplicate しますが、最初に target に対して ptrace-style permissions をチェックします。<sup>[[3]](#references)</sup> **teardown window** 中にその authorization が誤って許可されると、unprivileged attacker は次のものを copy できます。

- privileged helper がすでに開いている **sensitive files** の FD
- root としてすでに authorization されている **authenticated IPC channels** の FD

これにより、kernel-side authorization bug が非常に実用的な userspace primitive に変わります。<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

この attack には、privileged helper 自体の bug は必要ありません。helper は価値のあるものを一時的に保持していれば十分です。

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- その他、すでに開かれている secret または authorized channel

攻撃者の process に duplicate されると、その duplicate は同じ open file description を参照します。そのため、その後の read や IPC request は、元の pathname を再度 open したり、新しい authentication flow を開始したりするのではなく、すでに開かれている FD を使用します。<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. sensitive files を open したり、有用な IPC connections を保持したりする **setuid / setgid / file-capability binary** または **root daemon** を特定します。<sup>[[2]](#references)</sup>
2. target path に対する関連する ptrace policy checks を満たす relationship を確立します（たとえば、permissive YAMA settings 下で spawn された privileged child の **parent** になります）。<sup>[[2]](#references)[[4]](#references)</sup>
3. process が **exiting**、**dropping credentials**、または ptrace access が利用できなくなるべき状態へ移行している間に race を行います。<sup>[[2]](#references)</sup>
4. `pidfd_open()` + `pidfd_getfd()` を使用して、狭い authorization window の間に target FD を duplicate します。<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. unprivileged context から stolen FD を再利用します。<sup>[[2]](#references)</sup>
- `read()` で privileged file descriptor から secrets を読み取る
- stolen authenticated IPC channel 経由で requests を送信し、**root-side actions** を実行させる

Minimal primitive shape。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 監査対象として実用的な候補

短時間であっても、以下のいずれかを行うバイナリや daemon を優先します:<sup>[[1]](#references)[[2]](#references)</sup>

- 権限移行を完了する前に root-only ファイルを開く
- **system bus** に接続し、認証済みの channel を保持する
- helper の境界を越えて privileged FD を渡す
- `do_exit()` に隣接する teardown 中に security-sensitive な処理を行う

有望な hunting 候補:<sup>[[1]](#references)</sup>

- password / account management helper
- SSH helper
- PolicyKit / D-Bus mediated helper
- D-Bus method を公開する root desktop daemon

## exploit gate としての YAMA

`kernel.yama.ptrace_scope` は、ptrace-family abuse に対する重要な実用上の gate です:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: 古典的な same-UID ptrace の動作
- `1`: 通常は parent -> child の tracing を許可するため、一部の public exploit path を到達可能な状態に保つ
- `2`: attach-style access に `CAP_SYS_PTRACE` を要求し、この path における unprivileged `pidfd_getfd()` abuse をブロックする
- `3`: reboot まで ptrace attach を完全に無効化する

この technique において、`ptrace_scope=2` は強力な **temporary mitigation** です。unprivileged user に対する public `pidfd_getfd()` exploitation path を `-EPERM` で遮断できるためです。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review のアイデア

privileged Linux software を監査する際は、以下の組み合わせを探します:

- **privileged child process** + **attacker-controlled parent**。<sup>[[2]](#references)[[4]](#references)</sup>
- **valuable open files** への一時的な access
- **authenticated D-Bus/systemd channels** への一時的な access。<sup>[[2]](#references)</sup>
- classic `ptrace(2)` の外部で **ptrace-style authorization** を再利用する security decision
- 既存の privileged FD を **duplicate、inherit、または re-export** できる kernel API

kernel を監査する際は、**task teardown** 中に **ptrace-equivalent authorization** を行う path を high risk とみなします。特に、成功時に `task->files` や、その他の認証済み process resource へ直接 access できる場合は注意が必要です。<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Linux kernel の ptrace path における Local Root Privilege Escalation と Credential Disclosure (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
