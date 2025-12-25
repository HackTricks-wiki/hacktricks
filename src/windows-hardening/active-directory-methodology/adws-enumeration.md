# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) は **Windows Server 2008 R2 以降のすべてのドメインコントローラーでデフォルトで有効化**されており、TCP **9389** をリッスンします。名前に反して、**HTTP は関与しません**。代わりに、このサービスはプロプライエタリな .NET フレーミングプロトコルのスタックを通して LDAP スタイルのデータを公開します:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

これらのバイナリ SOAP フレーム内にトラフィックがカプセル化され、一般的でないポートを通るため、**ADWS 経由の enumeration は従来の LDAP/389 & 636 トラフィックよりも検査、フィルタ、シグネチャ検出を受ける可能性がはるかに低い**です。オペレーターにとっての利点は:

* よりステルスな recon — Blue team はしばしば LDAP クエリに注力します。
* SOCKS プロキシ経由で 9389/TCP をトンネリングすることで **non-Windows hosts (Linux, macOS)** からの収集が可能。
* LDAP で取得できるのと同じデータ（users, groups, ACLs, schema など）と、**writes** を行う能力（例: `msDs-AllowedToActOnBehalfOfOtherIdentity` による **RBCD**）。

ADWS の対話は WS-Enumeration 上で実装されています: すべてのクエリは LDAP フィルター/属性を定義する `Enumerate` メッセージで始まり、`EnumerationContext` GUID を返し、その後サーバー定義の結果ウィンドウまでストリームする 1 回以上の `Pull` メッセージが続きます。Context は約 30 分で期限切れになるため、ツールは結果をページングするかフィルターを分割（CN ごとのプレフィックスクエリ）して状態を失わないようにする必要があります。セキュリティ記述子を要求する場合は、SACL を省略するために `LDAP_SERVER_SD_FLAGS_OID` コントロールを指定してください。そうしないと ADWS は SOAP レスポンスから単に `nTSecurityDescriptor` 属性を落とします。

> NOTE: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されるため、トラフィックは正当な管理者アクティビティと混ざる可能性があります。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) は **純粋な Python で ADWS プロトコルスタックを完全再実装したもの**です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で作成し、.NET ランタイムに触れずに Unix 系システムからの収集を可能にします。

### Key Features

* **proxying through SOCKS** をサポート（C2 インプラントから有用）。
* LDAP の `-q '(objectClass=user)'` と同等の細かい検索フィルター。
* オプションの **write** 操作（`--set` / `--delete`）。
* BloodHound に直接取り込める **BOFHound output mode**。
* 人間が読みやすくするためのタイムスタンプ / `userAccountControl` を整形する `--parse` フラグ。

### Targeted collection flags & write operations

SoaPy は ADWS 上で最も一般的な LDAP ハンティングタスクを再現するキュレーション済みスイッチを搭載しています: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`、およびカスタム取得用の生の `--query` / `--filter` ノブ。これらを `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（ターゲット Kerberoasting 用の SPN 準備）、`--asrep`（`userAccountControl` の `DONT_REQ_PREAUTH` を反転）などの書き込みプリミティブと組み合わせます。

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じホスト/認証情報を使って即座に発見をweaponiseするには: `--rbcds` で RBCD-capable オブジェクトをダンプし、続けて `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して Resource-Based Constrained Delegation チェーンをステージします（完全な悪用手順は [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

### インストール（オペレーターホスト）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – 大規模 ADWS 収集 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) は .NET 製のコレクタで、すべての LDAP 相互作用を ADWS 内に留め、BloodHound v4 互換の JSON を出力します。  
一度 `objectSid`, `objectGUID`, `distinguishedName` と `objectClass` の完全なキャッシュを構築（`--buildcache`）し、その後は高ボリュームの `--bhdump`、`--certdump` (ADCS)、または `--dnsdump` (AD-integrated DNS) 実行時に再利用するため、DC から外に出る属性は約35個の重要属性だけになります。  
AutoSplit（`--autosplit --threshold <N>`）は、大規模フォレストで30分の EnumerationContext timeout を超えないように、CN プレフィックスでクエリを自動的にシャードします。

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
エクスポートした JSON は SharpHound/BloodHound のワークフローに直接組み込めます—下流のグラフ化のアイデアは [BloodHound methodology](bloodhound.md) を参照してください。AutoSplit は SOAPHound を数百万オブジェクト規模のフォレストで堅牢にしつつ、クエリ数を ADExplorer スタイルのスナップショットより低く抑えます。

## ステルス AD 収集ワークフロー

以下のワークフローは、ADWS 経由で **ドメイン & ADCS オブジェクト** を列挙し、それらを BloodHound JSON に変換して証明書ベースの攻撃パスを探索する方法を示します — すべて Linux から実行できます:

1. **Tunnel 9389/TCP** をターゲットネットワークから自分のマシンに転送します（例: Chisel、Meterpreter、SSH の dynamic port-forward など）。  `export HTTPS_PROXY=socks5://127.0.0.1:1080` をエクスポートするか、SoaPy’s `--proxyHost/--proxyPort` を使用します。

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
4. **BloodHound に変換:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP をアップロード**し、BloodHound GUI 上で `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` のような cypher クエリを実行して、証明書のエスカレーション経路（ESC1、ESC8 など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` の書き込み (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
これを `s4u2proxy`/`Rubeus /getticket` と組み合わせて、完全な **Resource-Based Constrained Delegation** チェーンを構築します（詳細は [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

## ツール概要

| 目的 | ツール | 備考 |
|---------|------|-------|
| ADWS 列挙 | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、読み取り/書き込み |
| 大量の ADWS ダンプ | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、キャッシュ優先、BH/ADCS/DNS モード |
| BloodHound 取り込み | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch ログを変換 |
| 証明書の乗っ取り | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS を経由してプロキシ可能 |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
