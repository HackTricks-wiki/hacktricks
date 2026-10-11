# Linux 호스트의 데이터베이스 및 비밀 정보

{{#include ../../banners/hacktricks-training.md}}

데이터베이스 및 애플리케이션 자격 증명은 지원하는 서비스와 같은 위치에 있는 경우가 많습니다. 계정이 데이터를 읽거나 권한이 필요한 작업을 실행할 수 있는지 테스트하기 전에 프로세스, 로컬 소켓 또는 포트, 설정, 자격 증명 파일을 파악하세요.

## 로컬 데이터 서비스 및 자격 증명 찾기

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

읽을 수 있는 애플리케이션 설정 파일, 배포 파일, 서비스 환경 파일, 백업에서 연결 문자열이나 키를 확인합니다. DB 프로세스의 Unix socket은 TCP listener와 접근 규칙이 다를 수 있습니다. 데이터베이스 권한은 OS 권한과 다릅니다. 복구한 DB password로는 해당 DB 계정에 할당된 역할만 사용할 수 있으며, 다른 경로가 입증되지 않는 한 그 이상의 접근은 불가능합니다. PostgreSQL에서는 row-level security 정책으로 한 역할의 레코드가 숨겨질 수 있고, 정책 관리 권한이 있는 역할은 해당 보기를 변경할 수 있습니다. 데이터 접근과 정책 관리를 구분하세요. [MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md), [PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md), [Redis](../../network-services-pentesting/6379-pentesting-redis.md)의 서비스별 가이드를 참고하세요.

다른 계정의 홈 디렉터리에 있는 읽기 가능한 자동화 스크립트에는 파일 이름에 password가 언급되지 않더라도 credential이 포함될 수 있습니다. 예를 들어 Python 스크립트가 `su`를 실행하고 [`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html)을 사용해 password 프롬프트에 리터럴 값을 전달할 수 있습니다. [`su`](https://man7.org/linux/man-pages/man1/su.1.html)는 여전히 자체 인증 정책을 적용합니다. 현재 사용자가 디렉터리를 탐색하고 해당 스크립트를 읽을 수 있는지, 리터럴 값이 대상 계정의 password인지, 계정 전환으로 간주하기 전에 credential이 여전히 유효한지 확인하세요. 스크립트가 성공적으로 실행되지 않아도 텍스트에 비밀이 노출될 수 있습니다. 수동 열거 결과에는 값을 출력하거나 로그인을 시도하지 말고 경로와 권한만 표시하세요.

읽을 수 있는 SQLite 애플리케이션 데이터베이스에는 수신 대기 중인 데이터베이스 서비스가 없어도 사용자 이름과 password hash가 들어 있을 수 있습니다. hash를 오프라인 감사 대상으로 간주하기 전에 스키마와 파일 권한을 확인하세요. 복구한 애플리케이션 password로 OS 계정이나 로컬 관리자 패널에 접근할 수 있다고 보려면 password 재사용을 별도로 확인해야 합니다. hash 형식이나 일치하는 사용자 이름만으로 password 재사용이 입증되지는 않습니다.

Apache OFBiz는 `runtime/data/derby/<database>/` 아래에 내장 Derby 데이터베이스를 사용할 수 있습니다. Derby의 `service.properties` 파일은 데이터베이스 디렉터리를 표시하며, 같은 상위 디렉터리에 있는 `seg0` 디렉터리에는 테이블 파일이 저장됩니다. `USER_LOGIN` 같은 애플리케이션 레코드를 확인하기 전에 데이터베이스 디렉터리 전체의 권한을 확인하세요. 표시 파일을 읽을 수 있다고 해서 테이블도 읽을 수 있거나, password를 복구할 수 있거나, 애플리케이션 credential이 Unix 계정에서 유효하다는 뜻은 아닙니다. 일반적인 열거 결과에 데이터베이스 내용이나 password hash를 포함하지 마세요. [Derby 데이터베이스 디렉터리 문서](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)와 [OFBiz 로그인 API](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)를 참고하세요.

TeamCity는 서버 데이터를 설정 가능한 데이터 디렉터리(대개 `.BuildServer`)에 저장합니다. `config/projects/<project>/pluginData/ssh_keys`, `config/database.properties`, 내장 HSQLDB를 사용하는 경우 `system/buildserver.*`, 그리고 `backup/TeamCity_Backup_*.zip`의 권한을 확인하세요. 업로드된 SSH key와 기타 보안 설정은 암호화되어 있을 수 있으므로, 경로를 읽을 수 있다는 사실만으로 사용 가능한 private key가 있다고 볼 수는 없습니다. 데이터베이스나 백업에는 애플리케이션 사용자와 password hash가 들어 있을 수 있습니다. 이를 Unix 계정에 사용하려면 password 재사용을 별도로 입증해야 합니다. 열거 중에는 key, hash 또는 데이터베이스 행을 출력하지 말고 경로와 접근 권한을 기록하세요. TeamCity의 [데이터 디렉터리](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html), [SSH key](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html), [백업](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html) 문서를 참고하세요.

Duplicati 백업 서버는 `Duplicati-server.sqlite`에 설정을 저장합니다. 데이터 디렉터리는 서비스 계정의 홈 디렉터리, `/var/lib/Duplicati` 또는 컨테이너 볼륨 아래에 있을 수 있으며, `--server-datafolder` 또는 `DUPLICATI_HOME`으로 위치를 변경할 수 있습니다. 읽을 수 있는 데이터베이스는 연결 credential과 서버 서명 자료가 들어 있을 수 있어 중요한 단서지만, 최신 설치에서는 민감한 필드를 암호화하고 디렉터리 접근을 제한할 수 있습니다. 권한을 실제 서버 계정 및 인증된 UI 또는 ServerUtil 접근 권한과 대조하세요. 해당 서버가 컨테이너에서 호스트의 `/`를 마운트한 상태로 root 권한으로 실행되면, 승인된 백업 복원 및 작업 hook을 통해 호스트 파일시스템 경계를 넘을 수 있습니다. 하지만 loopback listener나 데이터베이스 파일 이름만으로 제어 권한이 입증되지는 않습니다. 이전 릴리스의 nonce 기반 로그인 동작을 현재 버전에도 적용된다고 가정하지 마세요. 현재 버전은 다른 [인증 모델](https://docs.duplicati.com/technical-details/server-authentication-model)을 사용합니다. 버전별 자세한 내용은 Duplicati의 [서버 데이터베이스](https://docs.duplicati.com/database-and-storage/the-server-database) 및 [ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil) 문서를 참고하세요.

PostgreSQL에서는 `pg_policies`와 `pg_class.relrowsecurity`를 확인해 쿼리 결과가 필터링된 것인지 레코드가 없는 것인지 구분하세요. 정책을 변경하거나 비활성화하려면 적절한 테이블 소유권 또는 관리자 권한이 필요합니다. 별도로 leak된 유지 관리 계정에는 이런 권한이 있을 수 있으며, 애플리케이션 계정에는 없을 수 있습니다. 인증되지 않은 Redis listener는 별개의 보안 문제입니다. 이를 비밀 정보의 출처로 간주하기 전에 loopback에만 바인딩되어 있는지, 현재 연결에 protected mode 또는 ACL이 적용되는지 확인하세요.

## 키 및 토큰 저장소 검토하기

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH private key, agent socket, Kerberos cache, GPG keyring 또는 PKCS#12 bundle은 현재 사용자가 접근할 수 있고 필요한 passphrase 또는 policy가 사용을 허용할 때만 유용합니다. 먼저 소유권과 permissions를 확인하세요. 해당 접근 경로는 [users and sessions](../user-information/user-and-session-triage.md), [Linux AD](../user-information/linux-active-directory.md), [post-exploitation](../post-exploitation/README.md) 페이지에서 설명합니다. Git history, 오래된 backups, shell history에도 실행 중인 config를 정리한 뒤에도 secrets가 남아 있을 수 있습니다. 읽을 수 있는 `.git` directory에는 working tree가 비어 있어도 삭제된 source와 이전에 commit된 credentials가 보존될 수 있습니다. 자동화된 enumeration 중 내용을 덤프하는 대신 접근 권한을 확인하고 history를 직접 검토하세요.

`/boot`에서 읽을 수 있는 boot image도 살펴볼 archive 후보입니다. [Initramfs boot scripts and copied helpers](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html)에는 [`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html)에 key를 전달하는 custom logic이 포함될 수 있습니다. image의 접근 permissions를 확인하고, 승인된 offline copy에서 관련 boot script와 helper만 검토하세요. 내장되거나 파생된 disk-unlock passphrase가 Unix account password와 같은 것은 아닙니다. 이를 account 전환으로 간주하기 전에 helper의 입력값, 실제 boot 경로, 별도의 credential 재사용 여부를 확인하세요. 일반적인 enumeration에서는 image의 압축을 풀거나 helper를 실행하거나 후보 key를 출력하지 마세요.

Vault CLI는 [일반적으로 인증 token을 `~/.vault-token`에 캐시](https://developer.hashicorp.com/vault/docs/commands/token-helper)하지만, custom token helper는 다른 위치에 저장할 수 있습니다. 읽을 수 있는 경로는 credential 후보일 뿐입니다. secret engine에 접근할 수 있다고 추정하기 전에 token의 유효성과 policy를 확인하세요. [Vault SSH one-time passwords](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)의 경우 token은 의도한 account와 host가 role의 user 및 CIDR에 포함된 credentials를 발급할 권한이 있어야 합니다. 해당 host에는 SSH verification helper가 설정되어 있어야 하며 login도 허용해야 합니다. role에 `root`가 지정되어 있거나 token 파일이 있다는 사실만으로 root 접근이 입증되지는 않습니다. Passive enumeration에서는 token을 읽거나 OTP를 요청하지 말고 파일 경로만 기록하세요.

[KeePass 1.x는 `.kdb`, KeePass 2.x는 `.kdbx`를 사용합니다](https://keepass.info/help/v2/version.html). 다른 제품도 `.kdb` suffix를 사용할 수 있으므로, 일치하는 파일명은 암호화된 vault일 가능성으로 취급하세요. 읽을 수 있는 vault라도 필요한 master password 또는 key file이 없으면 항목을 확인할 수 없습니다. attachment로 저장된 SSH key는 별도의 후보이며, host 접근 여부를 검증해야 합니다. [KeePass는 image를 포함한 임의의 파일을 key file로 허용](https://keepass.info/help/base/keys.html)하지만, 주변에 있는 파일은 그 역할, 필요한 모든 master-key 구성 요소, 더 높은 권한의 account login이 각각 독립적으로 확인되기 전까지는 후보일 뿐입니다.

지원용 archive에는 KeePass vault와 process memory dump가 모두 포함될 수 있습니다. [2.54 이전 KeePass 2.x의 경우 CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)에 따라 해당 vault에 대응하는 dump에서 master password를 복구할 가능성이 있습니다. 암호화된 vault만 있거나 무관한 dump만 있는 경우는 충분하지 않습니다. 일반적인 enumeration 중에는 archive 항목과 접근 권한을 직접 확인하고, 대량으로 압축을 풀거나 secrets를 출력하지 마세요. PuTTY private key는 `.ppk` 파일 또는 vault 항목의 `PuTTY-User-Key-File` 텍스트로 나타날 수 있습니다. key가 사용될 account, 암호화 여부, 허용되는 host를 각각 확인하세요.

읽을 수 있는 `.har` HTTP archive에는 인증 headers, cookies, form fields를 포함한 browser requests와 responses가 보존될 수 있습니다. 이 파일은 직접 저장되거나 지원용 attachment 안에 들어 있을 수 있습니다. 먼저 소유권과 접근 권한을 확인한 뒤 관련 항목만 살펴보세요. 파일명만으로 credential을 재사용할 수 있다고 단정할 수는 없습니다. 자동화된 enumeration에서는 캡처된 값을 출력하지 말고 archive 경로만 나열하세요. [Microsoft Edge documentation](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file)에서 민감한 데이터 내보내기 옵션을 설명합니다.

암호화된 database backups의 경우 결론을 내리기 전에 읽을 수 있는 archive, 접근 가능한 private-key 자료, passphrase 필요 여부를 함께 확인하세요. 승인을 받은 경우, 보호된 key의 passphrase 복구와 복호화된 backup 데이터 검토는 별도의 수동 작업입니다. Database `root` credential은 Unix `root` credential과 다릅니다. 두 account 간 password 재사용 여부는 별도로 승인받아 검증해야 합니다. web application의 filesystem trust boundary로 인해 이러한 자료를 소유한 account에 노출될 수도 있습니다. [Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)를 참조하세요.

Container root와 host root는 별개의 identity입니다. container 내부에서 root가 된 뒤에만 읽을 수 있는 private SSH key로 host account에 인증할 수 있는 경우도 있지만, host가 해당 key를 허용해야 합니다. key 파일명이나 public-key comment만으로 그 접근이 입증되지는 않습니다. 마찬가지로 timestamp가 붙은 password-change 기록 옆에서 발견한 custom password generator는 수동 분석을 위한 단서일 뿐입니다. 시간값을 seed로 사용하는 non-cryptographic generator는 후보 seed 범위가 작을 수 있지만, timezone, clock precision, library 동작, 이후의 password 변경에 따라 재구성이 달라집니다. 승인된 경우에만 후보 credentials를 검증하고, 생성된 후보를 확인된 password로 간주하지 마세요.

container 내부의 service account는 directory에 접근할 수 있고 파일 permissions가 허용하는 경우, 권한이 높은 디렉터리로 보이는 곳에 있는 오래된 provisioning script를 읽을 수 있습니다. script에 포함된 application-admin password는 credential 노출의 단서이지 host-root 접근 권한이 아닙니다. script와 credential이 실제로 사용 중이었는지, 해당 값이 어떤 account에 속하는지, host account가 여전히 같은 password를 허용하는지 확인하세요. Passive enumeration 중에는 secret을 출력하거나 host 인증을 시도하지 말고 파일 경로와 접근 권한만 기록하세요.

읽을 수 있는 `.p12` 또는 `.pfx` bundle의 password가 application configuration에 노출되어 있다면 `openssl pkcs12 -info -in bundle.p12 -noout`으로 확인하세요. bundle에 내보낼 수 있는 private key가 포함되어 있으면 `openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key` 명령으로 암호화되지 않은 key를 저장합니다. 출력 파일을 안전하게 보호하고 분석 후 삭제하세요. 복구한 key는 실제로 일치하는 service 또는 ciphertext에만 사용하세요. bundle이 있다고 해서 그 private key가 다른 application에도 유용한 것은 아닙니다.
{{#include ../../banners/hacktricks-training.md}}
