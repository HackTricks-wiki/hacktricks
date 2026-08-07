# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

有用な **Linux kernel privesc pattern** は、**ptrace authorization bug** を **privileged process** からの **file descriptor theft** に変えることです。

Qualys の `__ptrace_may_access()` case study（CVE-2026-46333）では、攻撃者は **exiting または credentials を drop している privileged process** と race し、`pidfd_getfd()` を使用して攻撃者の process に FD を duplicate します。<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` は別の process から file descriptor を duplicate しますが、その前に target に対して ptrace-style permissions を確認します。この authorization が **teardown window** 中に誤って grant されると、unprivileged attacker は次のものを copy できます。

- privileged helper がすでに open している **sensitive files** の FD
- すでに root として authorized されている **authenticated IPC channels** の FD

これにより、kernel-side authorization bug が、非常に実用的な userspace primitive に変わります。<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

この attack では、privileged helper 自体に bug がある必要はありません。helper は一時的に価値のあるものを保持しているだけで十分です。

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- その他、すでに open されている secret または authorized channel

攻撃者の process に duplicate された後、kernel は元の pathname や新しい authentication flow ではなく、**stolen FD** に対する operation を enforce します。<sup>[[1]](#references)</sup>

## Exploitation pattern

1. sensitive files を open する、または有用な IPC connections を保持する **setuid / setgid / file-capability binary** または **root daemon** を特定します。
2. target path に対する関連する ptrace policy checks を満たす relationship を確立します（たとえば、permissive YAMA settings の下で spawn された privileged child の **parent** になります）。
3. process が **exiting**、**dropping credentials**、または ptrace access が利用できなくなるべき state に入っている間に race します。
4. `pidfd_open()` + `pidfd_getfd()` を使用して、狭い authorization window の間に target FD を duplicate します。
5. unprivileged context から stolen FD を再利用します。
- privileged file descriptor から `read()` で secrets を読み取る
- stolen authenticated IPC channel 経由で requests を送信し、**root-side actions** を実行させる<sup>[[1]](#references)</sup>

Minimal primitive shape:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 監査対象として実用的なターゲット

短時間であっても、以下のいずれかを行うバイナリやデーモンを優先します:<sup>[[1]](#references)</sup>

- 権限遷移を完了する前に root 専用ファイルを開く
- **system bus** に接続し、すでに認証済みの channel を保持する
- helper の境界を越えて privileged FD を渡す
- `do_exit()` に隣接する teardown 中に security-sensitive な処理を実行する

有望な候補:<sup>[[1]](#references)</sup>

- password / account management helper
- SSH helper
- PolicyKit / D-Bus mediated helper
- D-Bus method を公開する root desktop daemon

## exploit gate としての YAMA

`kernel.yama.ptrace_scope` は、ptrace-family abuse に対する実用上の主要な gate です:<sup>[[4]](#references)</sup>

- `0`: classical な same-UID ptrace の挙動
- `1`: 通常、parent -> child tracing を許可するため、一部の public exploit path を引き続き到達可能にする
- `2`: attach-style access に `CAP_SYS_PTRACE` が必要となり、この path における unprivileged `pidfd_getfd()` abuse をブロックする
- `3`: reboot まで ptrace attach を完全に無効化する

この technique では、`ptrace_scope=2` は強力な **temporary mitigation** です。unprivileged user に対して `-EPERM` を返し、public `pidfd_getfd()` exploitation path を破壊するためです。<sup>[[1]](#references)</sup>

## Detection / review のアイデア

privileged Linux software を監査する際は、以下の組み合わせを探します:

- **privileged child process** + **attacker-controlled parent**
- **valuable open files** への一時的な access
- **authenticated D-Bus/systemd channels** への一時的な access
- classic `ptrace(2)` の外部で **ptrace-style authorization** を再利用する security decision
- 既存の privileged FD を **duplicate、inherit、または re-export** できる kernel API

kernel を監査する際は、**task teardown** 中に **ptrace-equivalent authorization** を行う path を high risk とみなします。特に、成功時に `task->files` や、すでに認証済みのその他の process resource へ直接 access できる場合は注意が必要です。

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
