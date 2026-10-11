# 사용자, 세션 및 자격 증명 아티팩트

{{#include ../../banners/hacktricks-training.md}}

현재 셸을 소유한 ID부터 확인한 다음, 다른 사용자와 그룹, 활성 세션, 자격 증명 저장소를 열거합니다. [실제, 유효 및 저장된 사용자 ID](euid-ruid-suid.md) 페이지에서는 프로세스의 유효 권한이 로그인 계정과 다를 수 있는 이유를 설명합니다.

## ID 및 그룹 기반 액세스 열거하기

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`에는 `/etc/passwd`를 직접 읽을 때 누락될 수 있는 디렉터리 기반 계정이 포함됩니다. UID 0 계정, 로그인 셸, 홈 디렉터리, 보조 그룹, 그리고 설정상 예상과 달리 대화형 로그인이 허용되는 계정을 검토하세요. 위임된 접근 권한(`sudo`, `docker`, `disk`, `shadow` 등)은 [interesting groups](interesting-groups-linux-pe/README.md) 페이지를 참고하세요. 그룹 이름만으로 권한이 있다고 판단하기 전에 실제 파일시스템 ACL과 로컬 정책을 확인하세요.

[NSS가 `passwd`, `group` 또는 `shadow` 조회를 데이터베이스에 연결하는 경우](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html), 데이터베이스 기반 ID를 평가하기 전에 활성 provider와 해당 설정 경로를 확인하세요. PostgreSQL NSS 배포 환경에서 `/etc/nss-pgsql.conf`와 `/etc/nss-pgsql-root.conf`는 경로만 확인할 단서입니다. 연결 설정에 자격 증명이 포함될 수 있기 때문입니다. 데이터베이스 role은 활성 NSS provider가 실제로 반환하는 레코드를 변경할 수 있고, 계정이 해당 정보를 사용해 인증할 수 있는 경우에만 의미가 있습니다. 기본 GID가 0이면 root 그룹에 속할 뿐 UID 0이 되는 것은 아닙니다. sudo 그룹 매핑이 유효하려면 유효한 [sudoers 그룹 규칙](https://man7.org/linux/man-pages/man5/sudoers.5.html)과 필요한 인증이 있어야 합니다. UID 0 매핑은 별개의 ID 경계입니다. 수동 열거 중에는 연결 문자열을 출력하거나 계정 레코드를 변경하지 마세요.

또한 로컬 계정 이름 전체에서 숫자 UID를 비교하세요. [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html)의 이름 두 개가 같은 Unix 파일 ID를 가리킬 수 있지만, 로그인 인증 레코드는 서로 다를 수 있습니다. 따라서 인증에 성공한 후 새로 추가된 별칭이 다른 사용자의 파일이나 프로세스에 접근하게 될 수 있습니다. 단, 해당 UID가 0이거나 별도의 권한 경로가 있지 않는 한 root 권한을 부여하지는 않습니다. UID 공유는 의도적일 수도 있습니다. 계정 소스(`/etc/passwd` 또는 NSS), 생성 이력, 셸과 홈 디렉터리, 실제 인증 정책, 계정 간 ID 공유가 승인되었는지 확인하세요. 로컬 계정만 검사해서는 디렉터리 기반 별칭의 존재를 배제할 수 없습니다.

## 활성 및 최근 세션 확인

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` 또는 `tmux` 소켓은 권한이 허용하는 경우 현재 사용자가 연결할 수 있는 기존 셸을 노출할 수 있습니다. 접근을 시도하기 전에 소유자와 소켓 모드를 확인하세요. 다른 사용자의 세션에 자동으로 연결할 수 있는 것은 아닙니다. 활성화된 sudo 타임스탬프나 SSH agent 소켓도 중요할 수 있지만, 이를 재사용할 수 있는지는 사용자 식별 정보, 권한 및 정책에 따라 달라집니다. agent forwarding 악용에 대해서는 [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md)을 참조하세요.

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster)은 `SSH_AUTH_SOCK`과 별개입니다. `ControlMaster`와 `ControlPath`를 사용하면 이후의 SSH 클라이언트가 기존 인증 연결을 공유할 수 있으며, `ControlPersist`를 설정하면 첫 세션이 종료된 뒤에도 master를 계속 사용할 수 있습니다. 현재 사용자의 `.ssh/config`와 `.ssh` 내의 얕은 경로에 있는 소켓을 확인하고, 소유자와 권한도 살펴보세요. 소켓 파일 이름만으로는 master가 실행 중인지, 현재 사용자가 연결할 수 있는지, 어떤 원격 계정을 사용하는지 알 수 없습니다.

## 사용자 아티팩트 검토

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history, 시작 파일, SSH 키, 애플리케이션 구성, GPG 키링, Kerberos 캐시는 자격 증명이나 쓰기 가능한 지속성 지점을 드러낼 수 있습니다. 권한이 더 높은 계정의 `authorized_keys` 또는 셸 시작 파일을 수정할 수 있다면 검토해야 합니다. [post-exploitation 페이지](../post-exploitation/README.md)에서는 GPG homedir 재배치와 자격 증명 탐색을 다루고, [Linux Active Directory](linux-active-directory.md)에서는 Kerberos 캐시와 keytab 재사용을 다룹니다. [PAM 페이지](../software-information/pam-pluggable-authentication-modules.md)에서는 인증 정책의 위험을 설명합니다.
{{#include ../../banners/hacktricks-training.md}}
