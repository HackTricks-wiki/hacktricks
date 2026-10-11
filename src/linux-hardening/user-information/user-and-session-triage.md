# 用户、会话和凭据痕迹

{{#include ../../banners/hacktricks-training.md}}

先确认当前 shell 所属的身份，然后枚举其他用户、组、活动会话和凭据存储。[真实、有效和保存的用户 ID](euid-ruid-suid.md) 页面解释了为什么进程的有效权限可能与其登录账户不同。

## 枚举身份和基于组的访问权限

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` 会包含目录服务中的账户，而仅查看 `/etc/passwd` 可能会漏掉这些账户。检查 UID 0 账户、登录 shell、主目录、附加组，以及配置意外允许交互式登录的账户。[interesting groups](interesting-groups-linux-pe/README.md) 页面介绍了 `sudo`、`docker`、`disk` 和 `shadow` 等委派访问权限。在将组名视为特权之前，请检查实际文件系统 ACL 和本地策略。

如果 [NSS 将 `passwd`、`group` 或 `shadow` 查询映射到数据库](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)，请先检查正在使用的提供程序及其配置路径，再评估数据库支持的身份。对于 PostgreSQL NSS 部署，`/etc/nss-pgsql.conf` 和 `/etc/nss-pgsql-root.conf` 只能作为路径线索，因为连接设置中可能包含凭据。只有当某个数据库角色能够修改活动 NSS 提供程序实际返回的记录，且账户能够使用这些记录进行身份验证时，该角色才有意义。主 GID 为 0 表示属于 root 组，并不代表 UID 0；sudo 组映射需要有效的 [sudoers 组规则](https://man7.org/linux/man-pages/man5/sudoers.5.html)以及任何必要的身份验证。UID 0 映射则属于不同的身份边界。被动枚举期间，不要打印连接字符串或更改账户记录。

还应比较本地账户名对应的数字 UID。两个 [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) 中的名称可能对应同一个 Unix 文件身份，但它们的登录身份验证记录可能不同。因此，成功通过身份验证后，新添加的共享非零 UID 别名可能会访问另一用户的文件或进程；除非该 UID 本身或其他独立提权路径赋予 root 权限，否则它不会授予 root 权限。共享 UID 可能是有意设置的。请确认账户来源（`/etc/passwd` 还是 NSS）、创建历史、shell 和主目录、实际身份验证策略，以及这些账户是否获准共享该身份。仅检查本地重复项无法排除目录服务中的别名。

## 查找活动会话和近期会话

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` 或 `tmux` socket 的权限允许当前用户连接时，可能会暴露现有 shell。尝试访问前，先检查所有者和 socket 模式；其他用户的会话并非总能连接。活动的 sudo 时间戳或 SSH agent socket 也可能有影响，但能否复用取决于用户身份、权限和策略。有关 agent forwarding 滥用，请参阅 [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md)。

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) 与 `SSH_AUTH_SOCK` 不同：`ControlMaster` 和 `ControlPath` 可让后续 SSH 客户端共享已有的认证连接，而 `ControlPersist` 可在第一个会话结束后继续保持 master 可用。检查当前用户的 `.ssh/config` 和浅层 `.ssh` socket 路径，包括所有者和权限。仅凭 socket 文件名无法证明 master 仍在运行、当前用户可以连接，或它使用的是哪个远程账户。

## 审查用户痕迹

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell 历史记录、启动文件、SSH 密钥、应用程序配置、GPG 密钥环和 Kerberos 缓存可能泄露凭据或暴露可写的持久化入口。对于权限更高的账户，如果其 `authorized_keys` 或 shell 启动文件可写，就值得检查。[post-exploitation 页面](../post-exploitation/README.md)介绍了 GPG homedir 重定位和凭据搜寻；[Linux Active Directory](linux-active-directory.md)介绍了 Kerberos 缓存和 keytab 的复用。[PAM 页面](../software-information/pam-pluggable-authentication-modules.md)说明了身份验证策略风险。
{{#include ../../banners/hacktricks-training.md}}
