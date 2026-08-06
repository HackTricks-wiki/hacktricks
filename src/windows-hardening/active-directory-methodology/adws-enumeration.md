# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS とは？

Active Directory Web Services (ADWS) は、**Windows Server 2008 R2 以降、すべての Domain Controller でデフォルトで有効**になっており、TCP **9389** で待ち受けます。名前に反して、**HTTP は使用されません**。代わりに、独自の .NET framing protocol stack を通じて LDAP-style data を公開します。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

トラフィックはこれらの binary SOAP frames にカプセル化され、一般的ではない port を通過するため、**ADWS 経由の enumeration は、従来の LDAP/389 および 636 traffic と比べて、検査、filter、signature の対象になる可能性がはるかに低くなります**。operator にとって、これは次のことを意味します。<sup>[[1]](#references)[[7]](#references)</sup>

* より stealthy な recon – Blue team は LDAP queries に集中することが多い。
* **non-Windows hosts (Linux、macOS)** から、SOCKS proxy を介して 9389/TCP を tunneling することで収集できる。
* LDAP 経由で取得できるものと同じ data（users、groups、ACLs、schema など）に加え、**writes** を実行できる（例: **RBCD** 用の `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS interactions は WS-Enumeration 上に実装されています。すべての query は、LDAP filter/attributes を定義する `Enumerate` message から開始され、`EnumerationContext` GUID が返されます。その後、server-defined result window までを stream する 1 つ以上の `Pull` messages が続きます。<sup>[[7]](#references)</sup> Contexts は約 30 分後に expire するため、tooling は state の喪失を避けるために、results を page 処理するか、filters（CN ごとの prefix queries）を分割する必要があります。<sup>[[8]](#references)</sup> Security descriptors を要求する場合は、`LDAP_SERVER_SD_FLAGS_OID` control を指定して SACLs を省略してください。指定しない場合、ADWS は SOAP response から `nTSecurityDescriptor` attribute を単純に削除します。

> NOTE: ADWS は多くの RSAT GUI/PowerShell tools でも使用されるため、traffic が正規の admin activity に紛れ込む可能性があります。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) は、**ADWS protocol stack を pure Python で完全に再実装したもの**です。NBFX/NBFSE/NNS/NMF frames を byte-for-byte で構築するため、.NET runtime に触れることなく Unix-like systems から収集できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Key Features

* **SOCKS 経由の proxying** をサポート（C2 implants から使用する場合に便利）。
* LDAP の `-q '(objectClass=user)'` と同一の fine-grained search filters。
* Optional な **write** operations（ `--set` / `--delete` ）。
* BloodHound に直接 ingestion するための **BOFHound output mode**。
* 人間が読みやすい形式が必要な場合に、timestamps / `userAccountControl` を見やすく整形する `--parse` flag。<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

SoaPy には、最も一般的な LDAP hunting tasks を ADWS 上で再現する curated switches が含まれています。`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds` に加え、custom pulls 用の raw `--query` / `--filter` knobs も利用できます。これらを、`--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（targeted Kerberoasting 用の SPN staging）、`--asrep`（`userAccountControl` の `DONT_REQ_PREAUTH` を反転）などの write primitives と組み合わせます。<sup>[[2]](#references)</sup>

`samAccountName` と `servicePrincipalName` のみを返す、targeted SPN hunt の例:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/credentialsを使用して、findingsを直ちにweaponiseします。`--rbcds`でRBCD-capable objectsをdumpし、続いて`--rbcd 'WEBSRV01$' --account 'FILE01$'`を適用して、Resource-Based Constrained Delegation chainをstageします（完全なabuse pathについては[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)を参照）。

### Installation（operator host）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS（Linux/Windows）

* `ldapdomaindump` の fork で、LDAP-signature hits を減らすため、LDAP queries を TCP/9389 上の ADWS calls に置き換えます。
* `--force` が渡されない限り、9389 への初期 reachability check を実行します（port scans が noisy/filtered な場合は probe をスキップします）。
* Microsoft Defender for Endpoint および CrowdStrike Falcon に対してテスト済みで、README では bypass の成功が報告されています。<sup>[[4]](#references)</sup>

### インストール
```bash
pipx install .
```
### 使用方法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型的な出力には、9389 の到達可能性チェック、ADWS bind、dump の開始および終了が記録されます：
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang製の実用的な ADWS client

soapyと同様に、[sopa](https://github.com/Macmod/sopa) はGolangでADWS protocol stack（MS-NNS + MC-NMF + SOAP）を実装し、次のようなADWS callを実行するためのcommand-line flagsを提供します。<sup>[[5]](#references)</sup>

* **Objectの検索と取得** - `query` / `get`
* **Objectのライフサイクル管理** - `create [user|computer|group|ou|container|custom]` と `delete`
* **Attributeの編集** - `attr [add|replace|delete]`
* **Account管理** - `set-password` / `change-password`
* その他、`groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]` など

### Protocol mappingのポイント

* LDAP形式の検索は、attribute projection、scope制御（Base/OneLevel/Subtree）、paginationに対応した **WS-Enumeration**（`Enumerate` + `Pull`）経由で実行されます。
* 単一Objectの取得には **WS-Transfer** の `Get` を使用し、attributeの変更には `Put`、削除には `Delete` を使用します。
* 組み込みObjectの作成には **WS-Transfer ResourceFactory** を使用し、custom objectにはYAML templateによって駆動される **IMDA AddRequest** を使用します。
* Password操作は **MS-ADCAP** actions（`SetPassword`、`ChangePassword`）です。<sup>[[5]](#references)</sup>

### 認証なしの metadata discovery（mex）

ADWSはcredentialsなしでWS-MetadataExchangeを公開しているため、認証前にexposureを手早く確認できます。<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery & Kerberos targeting notes

Sopa は `--dc` が省略され、`--domain` が指定されている場合、SRV を介して DC を解決できます。以下の順序でクエリを実行し、最も優先度の高いターゲットを使用します。<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
運用上、セグメント化された環境での失敗を避けるため、DC管理のリゾルバーを優先して使用します。

* `--dns <DC-IP>` を使用すると、**すべての** SRV/PTR/forward lookup がDCのDNS経由になります。
* UDPがブロックされている場合、またはSRVの応答が大きい場合は、`--dns-tcp` を使用します。
* Kerberosが有効で、`--dc` がIPの場合、sopaは正しいSPN/KDCターゲティングのためにFQDNを取得する目的で **reverse PTR** を実行します。Kerberosを使用しない場合、PTR lookupは実行されません。

例（IP + Kerberos、DC経由でDNSを強制）：
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth material options

平文パスワード以外にも、sopa は ADWS auth に **NT hashes**、**Kerberos AES keys**、**ccache**、**PKINIT certificates**（PFX または PEM）を使用できます。`--aes-key`、`-c`（ccache）、または certificate-based options を使用すると、Kerberos が暗黙的に使用されます。<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### テンプレートによるカスタムオブジェクトの作成

任意のオブジェクトクラスの場合、`create custom` コマンドは IMDA の `AddRequest` にマッピングされる YAML template を受け取ります:<sup>[[5]](#references)</sup>

* `parentDN` と `rdn` はコンテナーと相対 DN を定義します。
* `attributes[].name` は `cn` または名前空間付きの `addata:cn` をサポートします。
* `attributes[].type` は `string|int|bool|base64|hex` または明示的な `xsd:*` を受け付けます。
* `ad:relativeDistinguishedName` や `ad:container-hierarchy-parent` は含めないでください。sopa が挿入します。
* `hex` 値は `xsd:base64Binary` に変換されます。空の文字列を設定するには `value: ""` を使用します。

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) は、すべての LDAP インタラクションを ADWS 内で実行し、BloodHound v4-compatible JSON を出力する .NET collector です。最初に `objectSid`、`objectGUID`、`distinguishedName`、`objectClass` の完全な cache を構築し（`--buildcache`）、その後これを再利用して、大量の `--bhdump`、`--certdump`（ADCS）、または `--dnsdump`（AD-integrated DNS）pass を実行するため、DC の外部に送信される critical attribute は約 35 個だけです。AutoSplit（`--autosplit --threshold <N>`）は、大規模な forest での 30 分間の EnumerationContext timeout を回避するため、CN prefix に基づいて query を自動的に shard します。<sup>[[8]](#references)</sup>

domain-joined operator VM での一般的な workflow:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
ExportしたJSONはSharpHound/BloodHound workflowsに直接取り込めます。下流のグラフ化のアイデアについては、[BloodHound methodology](bloodhound.md)を参照してください。AutoSplitにより、SOAPHoundはADExplorer形式のsnapshotよりもクエリ数を抑えながら、数百万オブジェクト規模のforestでも堅牢に動作します。

## ステルスAD Collection Workflow

以下のworkflowでは、LinuxからADWS経由で**domain & ADCS objects**をenumerateし、BloodHound JSONに変換して、certificate-based attack pathsを探索する方法を示します。

1. **9389/TCPをトンネル**して、target networkから自分のboxへ転送します（例：Chisel、Meterpreter、SSH dynamic port-forwardなどを使用）。`export HTTPS_PROXY=socks5://127.0.0.1:1080`を実行するか、SoaPyの`--proxyHost/--proxyPort`を使用します。

2. **root domain objectを収集します：**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC から ADCS 関連オブジェクトを収集する:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHoundへ変換：**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP を Upload** して BloodHound GUI で `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` などの cypher queries を実行し、certificate escalation paths（ESC1、ESC8 など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity`（RBCD）の書き込み
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
これを `s4u2proxy`/`Rubeus /getticket` と組み合わせることで、完全な **Resource-Based Constrained Delegation** chain を構築できます（[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

## Tooling Summary

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、cache-first、BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs を変換 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS 経由で proxy 可能 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS endpoints と interface する generic client。enumeration、object creation、attribute modifications、password changes が可能 |

## References

- [1] [SpecterOps – SOAP(y) を使用する – ADWS を使用した stealthy AD collection の Operator's Guide](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS を介した Active Directory environments の stealthy Enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS 経由で Active Directory data を collect する SOAPHound tool](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
