# 사용자, 세션 및 자격 증명 아티팩트

{{#include ../../banners/hacktricks-training.md}}

현재 셸을 소유한 ID부터 확인한 다음, 다른 사용자와 그룹, 활성 세션 및 자격 증명 저장소를 열거합니다. [실제, 유효 및 저장된 사용자 ID](euid-ruid-suid.md) 페이지에서는 프로세스의 유효 권한이 로그인 계정과 다를 수 있는 이유를 설명합니다.

## ID 및 그룹 기반 액세스 열거하기

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`에는 일반적인 `/etc/passwd` 읽기만으로는 확인할 수 없는 디렉터리 기반 계정도 포함됩니다. UID 0 계정, 로그인 셸, 홈 디렉터리, 보조 그룹, 그리고 설정상 대화형 로그인이 예상치 못하게 허용된 계정을 검토하세요. [interesting groups](interesting-groups-linux-pe/README.md) 페이지에서는 `sudo`, `docker`, `disk`, `shadow`와 같이 위임된 접근 권한을 다룹니다. 그룹 이름만 보고 권한이 있다고 판단하기 전에 실제 파일시스템 ACL과 로컬 정책을 확인하세요.

[NSS가 `passwd`, `group` 또는 `shadow` 조회를 데이터베이스에 매핑](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)하는 경우, 데이터베이스 기반 ID를 평가하기 전에 활성 provider와 해당 설정 경로를 검토하세요. PostgreSQL NSS 배포 환경에서 `/etc/nss-pgsql.conf`와 `/etc/nss-pgsql-root.conf`는 경로만 확인할 단서입니다. 연결 설정에 자격 증명이 포함될 수 있기 때문입니다. 데이터베이스 역할은 활성 NSS provider가 실제로 반환하는 레코드를 변경할 수 있고, 계정이 해당 레코드를 사용해 인증할 수 있는 경우에만 중요합니다. 기본 GID가 0이면 root 그룹에 속한다는 의미이지 UID 0이라는 뜻은 아닙니다. sudo 그룹 매핑에는 유효한 [sudoers 그룹 규칙](https://man7.org/linux/man-pages/man5/sudoers.5.html)과 필요한 인증이 있어야 합니다. UID 0 매핑은 별도의 ID 경계입니다. 수동 열거 중에는 연결 문자열을 출력하거나 계정 레코드를 변경하지 마세요.

로컬 계정 이름 간의 숫자 UID도 비교하세요. [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html)의 이름 두 개가 동일한 Unix 파일 ID를 가리킬 수 있지만, 로그인 인증 레코드는 서로 다를 수 있습니다. 따라서 인증에 성공하면 공유된 0이 아닌 UID를 가진 새 별칭을 통해 다른 사용자의 파일이나 프로세스에 접근할 수 있습니다. 단, 해당 UID 자체나 별도의 권한 경로가 없다면 root 권한을 얻는 것은 아닙니다. UID 공유는 의도적일 수 있습니다. 계정 출처(`/etc/passwd` 또는 NSS), 생성 이력, 셸과 홈 디렉터리, 실제 인증 정책, 그리고 계정 간 ID 공유가 승인되었는지를 확인하세요. 로컬 계정만 검사해서는 디렉터리 기반 별칭이 없다고 단정할 수 없습니다.

## 활성 및 최근 세션 찾기

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` 또는 `tmux` 소켓은 권한이 현재 사용자의 attach를 허용하는 경우 기존 셸을 노출할 수 있습니다. 접근을 시도하기 전에 소유자와 소켓 모드를 확인하세요. 다른 사용자의 세션이라고 해서 자동으로 attach할 수 있는 것은 아닙니다. 활성화된 sudo 타임스탬프나 SSH agent 소켓도 중요할 수 있지만, 재사용 가능 여부는 사용자 식별 정보, 권한 및 정책에 따라 달라집니다. agent forwarding 악용에 대해서는 [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md)을 참고하세요.

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster)은 `SSH_AUTH_SOCK`과 별개입니다. `ControlMaster`와 `ControlPath`를 사용하면 이후 SSH 클라이언트가 기존 인증 연결을 공유할 수 있고, `ControlPersist`를 사용하면 첫 번째 세션이 종료된 뒤에도 master를 사용할 수 있습니다. 현재 사용자의 `.ssh/config`와 `.ssh` 아래의 얕은 경로에 있는 소켓을 확인하고, 소유자와 권한도 살펴보세요. 소켓 파일명만으로는 master가 활성 상태인지, 현재 사용자가 연결할 수 있는지, 또는 어떤 원격 계정을 사용하는지 알 수 없습니다.

## 사용자 아티팩트 검토

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

셸 기록, 시작 파일, SSH 키, 애플리케이션 구성, GPG 키링, Kerberos 캐시는 자격 증명이나 쓰기 가능한 지속성 지점을 드러낼 수 있습니다. 권한이 더 높은 계정의 쓰기 가능한 `authorized_keys` 또는 셸 시작 파일은 검토할 가치가 있습니다. [post-exploitation 페이지](../post-exploitation/README.md)에서는 GPG homedir 재배치와 자격 증명 탐색을 다루며, [Linux Active Directory](linux-active-directory.md)에서는 Kerberos 캐시와 keytab 재사용을 다룹니다. [PAM 페이지](../software-information/pam-pluggable-authentication-modules.md)에서는 인증 정책의 위험을 설명합니다.
{{#include ../../banners/hacktricks-training.md}}
