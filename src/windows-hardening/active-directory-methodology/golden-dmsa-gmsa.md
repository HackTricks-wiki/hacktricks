# Golden gMSA/dMSA Attack（Managed Service Account 密码的离线派生）

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows Managed Service Account 是旨在运行服务的域主体，无需管理员处理长期有效的密码：

1. **gMSA**（group Managed Service Account）可供通过 `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword` 授权的计算机使用。
2. **dMSA**（delegated Managed Service Account）在 **Windows Server 2025** 中引入。它将常规身份验证绑定到已授权的计算机身份，并可通过迁移工作流替代旧版服务帐户。

不要将 **Golden dMSA** 与 **BadSuccessor** 混淆。Golden dMSA 需要攻陷 KDS root-key 材料，并据此派生 managed-account 密钥；而 [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) 则滥用对 dMSA 对象及其迁移属性的控制权。

DC 不会为每个 gMSA 分别存储独立生成的明文密码。它会根据 **KDS root key**、按时间索引的 Group Key Distribution Protocol (GKDI) 密钥以及帐户 SID 派生帐户密码。root-key 对象是位于 `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` 下的 `msKds-ProvRootKey` 对象；敏感值为 `msKds-RootKeyData`。`msDS-ManagedPasswordId` **不是 GUID**：它是一个二进制密钥标识符，其中包含 KDS root-key GUID、GKDI 的 `L0`/`L1`/`L2` 索引，以及域/林元数据。DC 使用标签 `GMSA PASSWORD` 和作为上下文的二进制 SID 应用 KDF，然后仅向获授权检索 gMSA 密码的主体公开 `MSDS-MANAGEDPASSWORD_BLOB`。<sup>[[2]](#references)</sup>

dMSA 在运行方式上通常有所不同：其 secret 应保留在 DC 上，由 KDC 向获授权的计算机签发凭据。然而，dMSA 会复用底层的 KDS/GKDI 密码派生机制。Golden dMSA 会直接重建该 secret，因此绕过预期的计算机绑定流程以及服务主机上的 Credential Guard。<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

提取 KDS root key 后，攻击者可以为与该密钥关联的帐户派生密码，而无需读取 `msDS-ManagedPassword`。这会绕过每个帐户的密码检索 ACL，并且只要被攻陷的 root key 仍在使用，就能在常规 managed-password 轮换后继续有效。对于 gMSA，可读的 `msDS-ManagedPasswordId` 通常会提供确切的密钥标识符。对于受 ACL 限制的 dMSA，Golden dMSA 会将缺失的标识符缩小为仅 **1,024 个候选值**。<sup>[[1]](#references)[[2]](#references)</sup>

### 前提条件

* 相关的 KDS root-key 对象，通常通过 Enterprise Admin / forest-root Domain Admin 权限、DC 上的 `SYSTEM`，或从暴露的 DC 数据库或备份中获取。<sup>[[1]](#references)[[2]](#references)</sup>
* 目标帐户的 SID、DNS 域、林名称和 `sAMAccountName`。<sup>[[1]](#references)[[2]](#references)</sup>
* 对于直接计算 gMSA，需要其 base64 编码的 `msDS-ManagedPasswordId`；对于 Golden dMSA，则可以改为猜测该值。<sup>[[1]](#references)[[2]](#references)</sup>
* 一个安装了 .NET Framework 4.7.2 的 x64 Windows 主机，用于运行 [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA)。<sup>[[3]](#references)</sup>

### 阶段 1 - 提取 KDS root key

`GoldenDMSA` 和 [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) 会将 root-key 对象字段导出为 base64 blob。不提供域参数时，这些工具会查询 forest root，并要求具有适当权限的目录访问权限。提供域/林参数后，DC 上的 `SYSTEM` 可以查询该 DC 的本地 Configuration 命名上下文副本。<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
记录 root-key GUID 和 base64 root-key blob。仅导出注册表 `SECURITY`/`SYSTEM` hive 并不等同于 KDS root key：权威材料位于 AD Configuration partition 中。<sup>[[1]](#references)[[2]](#references)</sup>

### 阶段 2 - 枚举 gMSA / dMSA 对象

对于 gMSA，获取 `sAMAccountName`、`objectSid` 和二进制 `msDS-ManagedPasswordId`。即使调用方无权检索 `msDS-ManagedPassword`，后者通常仍然可读。<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
dMSA 的默认 ACL 可能会阻止低权限 LDAP 枚举。`GoldenDMSA info` 可以查询 LDAP，也可以枚举候选 RID，并通过 `\PIPE\lsarpc` 上的 `LsaLookupSids` 解析 SIDs，然后区分 dMSA、计算机帐户和 gMSA。<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### 阶段 3 - 重构或猜测 `msDS-ManagedPasswordId`

该密钥标识符包含 `L0Index`、`L1Index` 和 `L2Index`，而不是由账户创建时间戳后跟随机位组成。Semperis 发现，密码生成路径不会使用候选 `L0Index`，而 `L1Index` 和 `L2Index` 的取值范围均限制为 `0..31`。因此，知道根密钥 GUID、domain、forest 和 SID 的攻击者可以构造全部 `32 * 32 = 1,024` 个候选标识符。<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
这些 derivation 是离线完成的，但识别 live candidate 通常需要进行 authentication attempts。在找到有效 key 之前，这可能会产生一连串失败的 Kerberos pre-authentication 或 NTLM validation。对于 AES Kerberos keys，tool 使用的 managed-account salt 为 `UPPERCASE.DNS.DOMAIN` + `host` + 去掉末尾 `$` 的小写 account UPN（例如 `EXAMPLE.LOCALhostsvc_dmsa.example.local`）。<sup>[[1]](#references)</sup>

### Phase 4 - 计算并使用 password

如果已知 exact identifier，则计算 256-byte password buffer，并将其转换为 NTLM/AES material。这些 tools 输出的 base64 value 是编码后的 password buffer，**而不是** LDAP `MSDS-MANAGEDPASSWORD_BLOB` 本身。<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
NTLM 结果可用于接受 NTLM 的场景；AES key 可用于 overpass-the-hash / TGT requests，即使 managed account 仅支持 AES。这使攻击者无需将其机器添加到 `PrincipalsAllowedToRetrieveManagedPassword`，即可获得被 compromise 的 managed service account 的权限、SPNs、delegation 配置和资源访问权限。<sup>[[1]](#references)[[2]](#references)</sup>

### 跨域 Configuration-partition abuse

KDS root-key objects 位于 forest Configuration naming context 中，并会复制到子域中的 DC。因此，子域 DC 上的 `SYSTEM` 可以从子 DC 的本地副本读取 forest-root KDS material，即使 child Domain Admins 无法直接从 forest-root DC 读取该 object。如果攻击者还可以读取 parent-domain gMSA 的 `msDS-ManagedPasswordId`，GoldenGMSA 就能计算出该 parent account 的 password；SID filtering 无法阻止这种 cryptographic attack。<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## 检测、遏制与恢复

* 在 **Master Root Keys** 容器上配置 SACL，并将其继承到 `msKds-ProvRootKey` 对象，以审计成功读取 `msKds-RootKeyData` 的操作。启用 Directory Service Access auditing 后，online extraction 会生成 Security 事件 **4662**；应调查不属于预期 DC 或 Tier-0 operators 的主体。同时审计对这些 SACL 和 root-key object ACL 的更改。<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* child-to-parent attack 会从受 compromized child DC 的本地副本读取 KDS 对象，因此 forest-root domain 可能无法观察到该读取。在 parent domain 中，审计对 `msDS-GroupManagedServiceAccount` 对象上 `msDS-ManagedPasswordId`（schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`）的成功读取，并调查来自其他 domain 的 principals 的读取操作。<sup>[[5]](#references)</sup>
* 将 KDS-object access 与 managed accounts 的异常 logons，以及以 `$` 结尾的 service accounts 出现的大量 Kerberos/NTLM failures 关联分析。此前发生 database/backup theft 后进行的 offline computation，live DC 无法观察到。<sup>[[1]](#references)[[3]](#references)</sup>
* root-key exposure 后，普通的 password rotation 并不足够。Microsoft 当前的 recovery procedure 会创建新的 KDS root key，重启所有相关 DC 上的 KDS，并将受影响的 accounts 转移到该 key。如果 exposure 范围或时间未知，且无法接受等待安全轮换，则替换所有使用 compromised key 的 gMSA；如果范围已知，Microsoft 提供了 authoritative-restore workflow，以强制执行安全 rolling。在删除旧 key 前，验证 `msDS-ManagedPasswordId` 中的新 key GUID。<sup>[[4]](#references)</sup>
* 将 DC database 和 backup access、Configuration-partition replication，以及 KDS root-key administration 视为 Tier-0。降低 `ManagedPasswordIntervalInDays` 可以缩短部分 recovery windows，但不会撤销已经 compromised 的 root key。<sup>[[4]](#references)</sup>

## 工具

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration、identifier generation、1,024-candidate validation、password computation，以及 NTLM/AES conversion。<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration，以及 online、offline 和 cross-domain password computation。<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) 和 [`Impacket`](https://github.com/fortra/impacket) - 在 authorised testing 中使用或验证派生出的 NTLM/AES keys。



## References

- [1] [Golden dMSA - delegated Managed Service Accounts 的 authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - 如何从 Golden gMSA attack 中恢复](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter as security boundary between domains? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
