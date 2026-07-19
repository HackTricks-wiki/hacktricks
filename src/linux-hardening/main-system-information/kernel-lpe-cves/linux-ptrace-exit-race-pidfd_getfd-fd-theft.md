# Linux ptrace exit-race `pidfd_getfd()` FD窃取

{{#include ../../../banners/hacktricks-training.md}}

有用な **Linux kernel privescパターン**の1つは、**ptrace authorization bug**を利用して、privileged processから**file descriptorを窃取**することです。

Qualysの`__ptrace_may_access()` case study（CVE-2026-46333）では、攻撃者は**privileged processが終了中、またはcredentialsを削除中**のタイミングをraceし、`pidfd_getfd()`を使ってFDを攻撃者のprocessにduplicateします。

## Core idea

`pidfd_getfd()`は別のprocessからfile descriptorをduplicateしますが、その前にtargetに対してptrace-style permissionsをチェックします。**teardown window**中にそのauthorizationが誤って許可されると、unprivileged attackerは以下をcopyできます。

- privileged helperがすでにopenしている**sensitive files**のFD
- rootとしてすでにauthorizationされている**authenticated IPC channels**のFD

これにより、kernel-side authorization bugが非常に実用的なuserspace primitiveに変わります。

## Why the primitive is dangerous

このattackでは、privileged helper自体にbugがある必要はありません。helperが一時的に価値のあるものを保持していれば十分です。

- `/etc/shadow`
- `/etc/ssh/*_key`
- privilegedなD-Bus / systemd connection
- その他、すでにopenされているsecretまたはauthorized channel

攻撃者のprocessにduplicateされた後、kernelは元のpathnameや新たなauthentication flowではなく、**stolen FD**に対してoperationsをenforceします。

## Exploitation pattern

1. sensitive filesをopenする、または有用なIPC connectionsを保持する**setuid / setgid / file-capability binary**または**root daemon**を特定する。
2. target pathに対する関連するptrace policy checksを満たすrelationshipを確立する（たとえば、permissiveなYAMA settingsのもとでspawnされたprivileged childの**parent**になる）。
3. processが**exiting**、**dropping credentials**、またはptrace accessが利用できなくなるべき状態へ移行している間にraceする。
4. `pidfd_open()` + `pidfd_getfd()`を使用し、狭いauthorization windowの間にtarget FDをduplicateする。
5. unprivileged contextからstolen FDを再利用する：
- privileged file descriptorからsecretを`read()`する
- stolen authenticated IPC channel経由でrequestを送信し、**root-side actions**を実行させる

Minimal primitive shape:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 実践的な監査対象

短時間でも次のいずれかを行うバイナリや daemon を優先します。

- privilege transition を完了する前に root 専用ファイルを開く
- **system bus** に接続し、認証済みの channel を保持する
- helper の境界を越えて privileged FD を渡す
- `do_exit()` に近い teardown 中に security-sensitive な処理を実行する

有望な調査対象:

- password / account management helper
- SSH helper
- PolicyKit / D-Bus mediated helper
- D-Bus メソッドを公開する root desktop daemon

## exploit gate としての YAMA

`kernel.yama.ptrace_scope` は ptrace-family abuse に対する、実用上の主要な gate です。

- `0`: classical な同一 UID の ptrace 動作
- `1`: 通常、parent -> child の tracing を許可するため、一部の public exploit path を到達可能な状態に保てる
- `2`: attach-style access に `CAP_SYS_PTRACE` を要求し、この path における unprivileged `pidfd_getfd()` abuse をブロックする
- `3`: reboot まで ptrace attach を完全に無効化する

この technique では、`ptrace_scope=2` は強力な **temporary mitigation** です。unprivileged user に対して `-EPERM` を返し、public な `pidfd_getfd()` exploitation path を破壊するためです。

## Detection / review のアイデア

privileged Linux software を監査する際は、次の組み合わせを探します。

- **privileged child process** + **attacker-controlled parent**
- **valuable open files** への一時的な access
- **authenticated D-Bus/systemd channels** への一時的な access
- classic な `ptrace(2)` 以外で **ptrace-style authorization** を再利用する security decision
- 既存の privileged FD を **duplicate、inherit、または re-export** できる kernel API

kernel を監査する際は、**task teardown** 中に **ptrace-equivalent authorization** を行う path を high risk とみなします。特に、成功時に `task->files` や、その他の認証済み process resource へ直接 access できる場合は注意が必要です。

## References

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
