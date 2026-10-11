# Linux 호스트의 데이터베이스 및 비밀 정보

{{#include ../../banners/hacktricks-training.md}}

데이터베이스 및 애플리케이션 자격 증명은 지원하는 서비스 옆에 저장되는 경우가 많습니다. 계정이 데이터를 읽거나 권한이 높은 작업을 실행할 수 있는지 테스트하기 전에 프로세스, 로컬 소켓 또는 포트, 구성, 자격 증명 파일을 파악하세요.

## 로컬 데이터 서비스 및 자격 증명 찾기

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

읽을 수 있는 애플리케이션 설정 파일, 배포 파일, 서비스 환경 파일 및 백업에서 연결 문자열이나 키를 확인하세요. DB 프로세스의 Unix 소켓은 TCP 리스너와 접근 규칙이 다를 수 있습니다. 데이터베이스 권한은 OS 권한과 다릅니다. 복구한 DB 비밀번호로는 해당 DB 계정에 할당된 역할만 사용할 수 있으며, 다른 경로는 별도로 입증해야 합니다. PostgreSQL에서 행 수준 보안 정책은 특정 역할에 레코드를 숨길 수 있으며, 정책 관리 권한이 있는 역할은 해당 보기를 변경할 수 있습니다. 데이터 접근 권한과 정책 관리 권한을 구분하세요. [MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md), [PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md), [Redis](../../network-services-pentesting/6379-pentesting-redis.md)에 관한 서비스별 가이드를 참고하세요.

다른 계정의 홈 디렉터리에서 읽을 수 있는 자동화 스크립트는 파일명에 비밀번호가 언급되지 않더라도 인증 정보를 포함할 수 있습니다. 예를 들어 Python 스크립트가 `su`를 실행한 뒤 [`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html)을 사용해 비밀번호 프롬프트에 값을 전달할 수 있습니다. [`su`](https://man7.org/linux/man-pages/man1/su.1.html)는 여전히 자체 인증 정책을 적용합니다. 해당 디렉터리를 탐색하고 정확한 스크립트를 읽을 수 있는 현재 사용자의 권한, 해당 값이 대상 계정의 비밀번호인지, 그리고 인증 정보가 여전히 유효한지 확인한 뒤에야 이를 계정 전환으로 간주하세요. 스크립트가 정상 실행되지 않더라도 내용에서 비밀 정보가 노출될 수 있습니다. 수동적 출력에는 값을 표시하거나 로그인을 시도하지 말고 경로와 권한만 나타내세요.

읽을 수 있는 SQLite 애플리케이션 데이터베이스에는 실행 중인 데이터베이스 서비스가 없어도 사용자 이름과 비밀번호 해시가 포함될 수 있습니다. 해시를 오프라인 감사의 단서로 취급하기 전에 스키마와 파일 권한을 확인하세요. 복구한 애플리케이션 비밀번호를 OS 계정이나 로컬 관리자 패널에 사용할 수 있다고 판단하려면 비밀번호 재사용 여부를 별도로 확인해야 합니다. 해시 형식이나 일치하는 사용자 이름만으로는 재사용이 입증되지 않습니다.

Apache OFBiz는 `runtime/data/derby/<database>/` 아래에 내장 Derby 데이터베이스를 사용할 수 있습니다. Derby의 `service.properties` 파일은 데이터베이스 디렉터리를 나타내며, 같은 디렉터리의 `seg0`에는 테이블 파일이 있습니다. `USER_LOGIN` 같은 애플리케이션 레코드를 살펴보기 전에 데이터베이스 디렉터리 전체의 권한을 확인하세요. 표시 파일을 읽을 수 있다고 해서 테이블도 읽을 수 있거나, 비밀번호를 복구할 수 있거나, 애플리케이션 인증 정보를 Unix 계정에 사용할 수 있는 것은 아닙니다. 일반적인 열거 출력에 데이터베이스 내용과 비밀번호 해시를 포함하지 마세요. [Derby 데이터베이스 디렉터리 문서](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)와 [OFBiz 로그인 API](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)를 참고하세요.

TeamCity는 서버 데이터를 설정 가능한 데이터 디렉터리(흔히 `.BuildServer`)에 저장합니다. `config/projects/<project>/pluginData/ssh_keys`, `config/database.properties`, 내장 HSQLDB를 사용하는 경우 `system/buildserver.*`, 그리고 `backup/TeamCity_Backup_*.zip`의 권한을 확인하세요. 업로드한 SSH 키와 기타 보안 설정은 암호화되어 있을 수 있으므로, 경로를 읽을 수 있다는 사실만으로 사용 가능한 개인 키가 있다고 볼 수는 없습니다. 데이터베이스나 백업에는 애플리케이션 사용자 및 비밀번호 해시가 들어 있을 수 있습니다. 이를 Unix 계정에 사용하려면 비밀번호 재사용을 입증하는 별도 근거가 필요합니다. 열거 중에는 키, 해시 또는 데이터베이스 행을 출력하지 말고 경로와 접근 권한을 기록하세요. TeamCity의 [데이터 디렉터리](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html), [SSH 키](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html), [백업](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html) 문서를 참고하세요.

Duplicati 백업 서버는 설정을 `Duplicati-server.sqlite`에 저장합니다. 데이터 디렉터리는 서비스 계정의 홈 디렉터리, `/var/lib/Duplicati` 또는 컨테이너 볼륨에 있을 수 있으며, `--server-datafolder` 또는 `DUPLICATI_HOME`으로 위치를 변경할 수 있습니다. 이 데이터베이스에는 연결 인증 정보와 서버 서명 자료가 들어 있을 수 있으므로 읽을 수 있다면 중요한 단서가 됩니다. 하지만 최신 설치에서는 민감한 필드를 암호화하거나 디렉터리 접근을 제한할 수 있습니다. 데이터베이스 권한을 실제 서버 계정 및 인증된 UI나 ServerUtil 접근과 대조하세요. 해당 서버가 호스트의 `/`를 컨테이너에 마운트한 상태로 root 권한으로 실행 중이라면, 권한이 부여된 백업 복원 및 작업 훅을 통해 호스트 파일시스템 경계를 넘을 수 있습니다. 하지만 루프백 리스너나 데이터베이스 파일명만으로 제어 권한이 입증되지는 않습니다. 이전 버전의 nonce 기반 로그인 동작이 현재 버전에도 적용된다고 가정하지 마세요. 현재 버전은 다른 [인증 모델](https://docs.duplicati.com/technical-details/server-authentication-model)을 사용합니다. 버전별 자세한 내용은 Duplicati의 [서버 데이터베이스](https://docs.duplicati.com/database-and-storage/the-server-database) 및 [ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil) 문서를 참고하세요.

PostgreSQL에서는 `pg_policies`와 `pg_class.relrowsecurity`를 확인해 쿼리 결과가 필터링된 것인지 레코드가 없는 것인지 구분하세요. 정책을 변경하거나 비활성화하려면 적절한 테이블 소유권 또는 관리자 권한이 필요합니다. 별도로 leak된 유지보수 계정에 이러한 권한이 있을 수 있지만 애플리케이션 계정에는 없을 수도 있습니다. 인증되지 않은 Redis 리스너는 별개의 발견 사항입니다. 이를 비밀 정보의 출처로 간주하기 전에 루프백에만 바인딩되어 있는지, 그리고 protected mode나 ACL이 현재 연결을 제한하는지 확인하세요.

## 키 및 토큰 저장소 검토하기

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH private key, agent socket, Kerberos cache, GPG keyring 또는 PKCS#12 bundle은 현재 사용자가 접근할 수 있고 필요한 passphrase나 정책이 사용을 허용할 때만 유용합니다. 먼저 소유권과 권한을 확인하세요. 해당 접근 경로는 [users and sessions](../user-information/user-and-session-triage.md), [Linux AD](../user-information/linux-active-directory.md), [post-exploitation](../post-exploitation/README.md) 페이지에서 설명합니다. Git history, 오래된 백업, shell history에도 live config를 정리한 뒤에도 secrets가 남아 있을 수 있습니다. 읽을 수 있는 `.git` 디렉터리는 working tree가 비어 있어도 삭제된 소스와 이전에 커밋된 credentials를 보존할 수 있습니다. automated enumeration 중 내용을 덤프하지 말고, 접근 권한을 확인한 뒤 history를 수동으로 검토하세요.

`/boot`에서 읽을 수 있는 boot image도 아카이브를 찾을 단서입니다. [Initramfs boot scripts and copied helpers](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html)에는 [`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html)에 key를 전달하는 custom logic이 포함될 수 있습니다. image의 접근 권한을 확인하고, 권한이 있는 offline 사본에서 관련 boot script와 helper만 검토하세요. 포함되었거나 파생된 disk-unlock passphrase가 Unix account password와 동일한 것은 아닙니다. 이를 account 전환으로 간주하기 전에 helper의 입력, 실제 boot 경로, 별도의 credential 재사용 여부를 확인하세요. 일반적인 enumeration에서는 image를 풀거나 helper를 실행하거나 후보 key를 출력하지 않아야 합니다.

Vault CLI는 [일반적으로 인증 token을 `~/.vault-token`에 캐시](https://developer.hashicorp.com/vault/docs/commands/token-helper)하지만, custom token helper는 다른 위치에 저장할 수 있습니다. 읽을 수 있는 경로는 credential을 찾을 단서일 뿐입니다. secret engine에 접근할 수 있다고 추정하기 전에 token의 유효성과 policy를 확인하세요. [Vault SSH one-time password](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)의 경우 token에 자격 증명을 발급할 권한이 있어야 하며, 해당 role의 user와 CIDR이 대상 account 및 host를 포함해야 합니다. 또한 host에 SSH verification helper가 설정되어 있어야 하며 로그인을 허용해야 합니다. role에 `root`라는 이름이 있거나 token 파일이 있다는 사실만으로 root access가 입증되지는 않습니다. Passive enumeration에서는 token을 읽거나 OTP를 요청하지 말고 파일 경로만 기록하세요.

[KeePass 1.x는 `.kdb`를, KeePass 2.x는 `.kdbx`를 사용합니다](https://keepass.info/help/v2/version.html). 다른 제품도 `.kdb` 확장자를 사용할 수 있으므로, 해당 파일명은 암호화된 vault일 가능성으로 취급하세요. 읽을 수 있는 vault라도 필요한 master password 또는 key file 없이는 항목을 볼 수 없습니다. 첨부 파일로 저장된 SSH key는 별도의 단서이며, 해당 host에 대한 접근 가능성을 검증해야 합니다. [KeePass는 이미지를 포함한 임의의 파일을 key file로 허용](https://keepass.info/help/base/keys.html)하지만, 근처에 있는 파일은 그 역할, 필요한 모든 master-key 구성 요소, 더 높은 권한의 account 로그인 여부를 각각 확인하기 전까지는 후보에 불과합니다.

지원 아카이브에는 KeePass vault와 process memory dump가 함께 들어 있을 수 있습니다. [KeePass 2.x 2.54 이전 버전에서는 CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)로 인해 해당 vault에 대응하는 dump에서 master password를 복구할 가능성이 있습니다. 암호화된 vault만 있거나 관련 없는 dump만 있는 경우에는 충분하지 않습니다. 일반적인 enumeration 중에는 대량으로 압축을 풀거나 secrets를 출력하지 말고, 아카이브 항목과 접근 권한을 수동으로 확인하세요. PuTTY private key는 `.ppk` 파일이나 vault 항목의 `PuTTY-User-Key-File` 텍스트로 나타날 수 있습니다. key의 대상 account, 암호화 여부, 허용되는 host를 각각 확인하세요.

읽을 수 있는 `.har` HTTP archive에는 authentication header, cookie, form field를 비롯한 browser request와 response가 남아 있을 수 있습니다. 파일로 직접 저장되거나 지원 첨부 파일에 포함될 수 있습니다. 먼저 소유권과 접근 권한을 확인한 뒤 관련 항목만 살펴보세요. 파일명만으로 재사용 가능한 credential이 있다고 단정할 수는 없습니다. Automated enumeration에서는 캡처된 값을 출력하지 말고 아카이브 경로만 나열하세요. [Microsoft Edge documentation](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file)에서 민감한 데이터 내보내기 옵션을 설명합니다.

암호화된 database backup의 경우 결론을 내리기 전에 읽을 수 있는 아카이브, 접근 가능한 private-key material, passphrase 필요 여부를 함께 확인하세요. 권한이 있는 경우에도 보호된 key의 passphrase 복구와 복호화된 backup 데이터 검토는 별도의 수동 단계입니다. Database `root` credential은 Unix `root` credential과 다릅니다. 두 account 간 password 재사용 여부는 별도로, 권한을 얻어 검증해야 합니다. 웹 애플리케이션의 filesystem trust boundary로 인해 해당 자료를 소유한 account가 노출될 수도 있습니다. [Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)를 참조하세요.

Container root와 host root는 서로 다른 identity입니다. container 내부에서 root가 된 뒤에만 읽을 수 있는 private SSH key라도 host에서 이를 허용한다면 host account에 인증할 수 있습니다. 그러나 key 파일명이나 public-key comment만으로 해당 접근이 입증되지는 않습니다. 마찬가지로 timestamp가 기록된 password 변경 내역 옆에서 발견한 custom password generator는 수동 분석을 위한 단서일 뿐입니다. 시간 기반의 비암호학적 generator는 후보 seed 범위가 작을 수 있지만, timezone, clock precision, library 동작, 이후 password 변경 여부가 복원에 영향을 줍니다. 권한이 있는 경우에만 후보 credential을 검증하세요. 생성된 후보를 확인된 password로 간주하지 마세요.

Container 내부의 service account는 디렉터리에 접근할 수 있고 파일 권한이 허용한다면, 명목상 권한이 높은 home directory에 있는 오래된 provisioning script를 읽을 수 있습니다. script에 포함된 application-admin password는 credential 노출의 단서이지 host-root access의 증거가 아닙니다. script와 credential이 실제로 사용 중이었는지, 해당 값이 어떤 account의 것인지, 별도의 host account에서 같은 password를 아직 허용하는지 확인하세요. Passive enumeration 중에는 secret을 출력하거나 host 인증을 시도하지 말고 파일 경로와 접근 권한을 기록하세요.

읽을 수 있는 `.p12` 또는 `.pfx` bundle의 password가 application configuration에 노출된 경우 `openssl pkcs12 -info -in bundle.p12 -noout`으로 확인하세요. bundle에 export 가능한 private key가 들어 있다면 `openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key` 명령은 해당 key를 암호화하지 않고 기록합니다. 출력 파일을 안전하게 보호하고 분석이 끝나면 삭제하세요. 복구한 key는 실제로 일치하는 service 또는 ciphertext에만 사용하세요. bundle이 있다고 해서 그 안의 private key를 다른 application에 유용하게 사용할 수 있는 것은 아닙니다.
{{#include ../../banners/hacktricks-training.md}}
