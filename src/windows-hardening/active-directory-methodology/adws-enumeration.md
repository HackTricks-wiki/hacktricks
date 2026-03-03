# Active Directory Web Services (ADWS) の列挙とステルス収集

{{#include ../../banners/hacktricks-training.md}}

## ADWSとは？

Active Directory Web Services (ADWS) は **Windows Server 2008 R2 以降の全ての Domain Controller でデフォルトで有効化されており**、TCP **9389** をリスンします。名前とは裏腹に、**HTTP は関与しません**。代わりに、このサービスは LDAP スタイルのデータを .NET 固有のフレーミングプロトコル群を通して公開します:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

これらのバイナリ SOAP フレーム内にトラフィックがカプセル化され、一般的でないポートを経由して送信されるため、**ADWS 経由の列挙は従来の LDAP/389 & 636 トラフィックに比べて検査・フィルタ・シグネチャ検出される可能性がかなり低くなります**。オペレーターにとっての利点は次の通りです:

* よりステルスな偵察 — Blue team はしばしば LDAP クエリに注力するため検知されにくい。
* SOCKS プロキシで 9389/TCP をトンネリングすることで、**非 Windows ホスト（Linux、macOS）** から収集可能。
* LDAP で得られるのと同じデータ（users、groups、ACLs、schema など）と、書き込みの実行能力（例: `msDs-AllowedToActOnBehalfOfOtherIdentity` による **RBCD**）を保持。

ADWS のやり取りは WS-Enumeration 上で実装されています：あらゆるクエリは LDAP フィルタ/属性を定義する `Enumerate` メッセージで開始され、`EnumerationContext` GUID を返し、その後サーバ定義の結果ウィンドウまでストリームする一つ以上の `Pull` メッセージが続きます。コンテキストは約 30 分で期限切れになるため、ツールは結果をページングするかフィルタを分割（CN ごとのプレフィックスクエリなど）して状態を失わないようにする必要があります。セキュリティディスクリプタを要求する際は `LDAP_SERVER_SD_FLAGS_OID` コントロールを指定して SACL を省くようにしてください。そうしないと ADWS は SOAP レスポンスから単純に `nTSecurityDescriptor` 属性を落とします。

> NOTE: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されているため、トラフィックは正当な管理者活動と混在する可能性があります。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) は **純粋な Python による ADWS プロトコルスタックの完全な再実装** です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で組み立てられるため、.NET ランタイムに触れることなく Unix 系システムから収集できます。

### 主な機能

* **SOCKS 経由のプロキシ**をサポート（C2 インプラントからの利用に便利）。
* LDAP の `-q '(objectClass=user)'` と同等の詳細な検索フィルタ。
* 任意の **書き込み** 操作（ `--set` / `--delete` ）。
* BloodHound に直接取り込める **BOFHound 出力モード**。
* 人間の可読性が必要な場合のタイムスタンプ / `userAccountControl` の整形用に `--parse` フラグ。

### ターゲット収集フラグ & 書き込み操作

SoaPy は ADWS 上で最も一般的な LDAP ハンティング作業を再現するキュレート済みのスイッチを搭載しています: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`、およびカスタム取得のための生の `--query` / `--filter` ノブ。これらを `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（ターゲット Kerberoasting 用の SPN ステージング）、`--asrep`（`userAccountControl` の `DONT_REQ_PREAUTH` を反転）などの書き込みプリミティブと組み合わせて使用します。

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/認証情報を使って発見を即時に武器化します: RBCD-capable オブジェクトを `--rbcds` でダンプし、続いて `--rbcd 'WEBSRV01$' --account 'FILE01$'` を実行して Resource-Based Constrained Delegation チェーンを仕込みます（完全な悪用経路は [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

### インストール (オペレーター ホスト)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - ADWS の実用的なクライアント (Golang)

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **オブジェクト検索と取得** - `query` / `get`
* **オブジェクトのライフサイクル** - `create [user|computer|group|ou|container|custom]` and `delete`
* **属性編集** - `attr [add|replace|delete]`
* **アカウント管理** - `set-password` / `change-password`
* その他 `groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]` など

## SOAPHound – 大量 ADWS 収集 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. It builds a complete cache of `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` once (`--buildcache`), then re-uses it for high-volume `--bhdump`, `--certdump` (ADCS), or `--dnsdump` (AD-integrated DNS) passes so only ~35 critical attributes ever leave the DC. AutoSplit (`--autosplit --threshold <N>`) automatically shards queries by CN prefix to stay under the 30-minute EnumerationContext timeout in large forests.

ドメイン参加済みの操作用 VM での典型的なワークフロー：
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
エクスポートされたJSONはSharpHound/BloodHoundワークフローに直接投入できます—下流のグラフ化のアイデアについては [BloodHound methodology](bloodhound.md) を参照してください。AutoSplitによりSOAPHoundは数百万オブジェクト規模のフォレストでも耐性を持ち、クエリ数はADExplorerスタイルのスナップショットより低く抑えられます。

## ステルスAD収集ワークフロー

以下のワークフローは、ADWS経由で**ドメイン & ADCSオブジェクト**を列挙し、それらをBloodHound JSONに変換して証明書ベースの攻撃パスを探索する方法を示します—すべてLinuxから実行します:

1. **Tunnel 9389/TCP** をターゲットネットワークから自分のマシンへトンネルする（例: Chisel、Meterpreter、SSHの動的ポートフォワードなど）。`export HTTPS_PROXY=socks5://127.0.0.1:1080` を設定するか、SoaPy’s `--proxyHost/--proxyPort` を使用する。

2. **Collect the root domain object:**
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
5. **ZIPをアップロード**し、BloodHound GUIで `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` のようなcypherクエリを実行して、証明書の昇格パス（ESC1、ESC8など）を明らかにします。

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
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch のログを変換 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS を経由してプロキシ可能 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS エンドポイントと連携する汎用クライアント - 列挙、オブジェクト作成、属性変更、パスワード変更が可能 |

## 参考

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
