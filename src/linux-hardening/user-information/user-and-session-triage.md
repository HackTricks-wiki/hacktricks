# Users, Sessions, and Credential Artifacts

{{#include ../../banners/hacktricks-training.md}}

Start with the identity that owns the current shell, then enumerate other users, groups, active sessions, and credential stores. The [real, effective, and saved user ID](euid-ruid-suid.md) page explains why a process's effective privileges may differ from its login account.

## Enumerate identities and group-based access

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` includes directory-backed accounts that a plain read of `/etc/passwd` can miss. Review UID 0 accounts, login shells, home directories, supplementary groups, and accounts whose configuration unexpectedly permits interactive login. The [interesting groups](interesting-groups-linux-pe/README.md) page covers delegated access such as `sudo`, `docker`, `disk`, and `shadow`. Check actual filesystem ACLs and local policy before treating a group name as a privilege.

## Find active and recent sessions

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

A `screen` or `tmux` socket can expose an existing shell if its permissions allow the current user to attach. Check the owner and socket mode before attempting access; another user's session is not automatically attachable. An active sudo timestamp or SSH agent socket may also matter, but their reuse depends on user identity, permissions, and policy. For agent forwarding abuse, see [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

## Review user artifacts

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history, startup files, SSH keys, application configuration, GPG keyrings, and Kerberos caches can reveal credentials or writable persistence points. A writable `authorized_keys` or shell startup file for a more privileged account deserves review. The [post-exploitation page](../post-exploitation/README.md) covers GPG homedir relocation and credential hunting; [Linux Active Directory](linux-active-directory.md) covers Kerberos cache and keytab reuse. The [PAM page](../software-information/pam-pluggable-authentication-modules.md) explains authentication-policy risks.
{{#include ../../banners/hacktricks-training.md}}
