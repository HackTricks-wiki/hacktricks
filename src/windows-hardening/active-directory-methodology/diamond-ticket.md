# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket は、任意のユーザーとして任意のサービスにアクセスするために使用できる TGT です。golden ticket は完全にオフラインで偽造され、そのドメインの krbtgt ハッシュで暗号化されてからログオン セッションに注入されます。ドメイン コントローラーは自分が正当に発行した TGT を追跡しないため、krbtgt ハッシュで暗号化された TGT を喜んで受け入れます。

golden ticket の使用を検出する一般的な手法は次の二つです:

- 対応する AS-REQ のない TGS-REQ を探す。
- Mimikatz のデフォルトの 10-year lifetime のような不自然な TGT を探す。

diamond ticket は DC によって発行された正当な TGT のフィールドを変更して作成されます。これは、TGT を要求し（requesting）、ドメインの krbtgt キーで復号し（decrypting）、チケットの目的のフィールドを修正し（modifying）、再暗号化する（re-encrypting）ことで達成されます。これにより golden ticket の上記二つの欠点を克服できます:

- TGS-REQ には前段の AS-REQ が存在する。
- TGT は DC によって発行されるため、domain の Kerberos ポリシーから正しい詳細をすべて含みます。これらは golden ticket でも正確に偽造できますが、より複雑でミスが起きやすいです。

### Requirements & workflow

- **Cryptographic material**: TGT を復号／再署名するための krbtgt AES256 key（推奨）または NTLM hash。
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u`、またはメモリからのチケットエクスポートで取得したもの。
- **Context data**: 対象ユーザーの RID、グループの RIDs/SIDs、（オプションで）LDAP から取得した PAC 属性。
- **Service keys**（service ticket を再発行する場合のみ）: 乗っ取り対象のサービス SPN の AES key。

1. AS-REQ により制御下の任意のユーザーの TGT を取得する（Rubeus の `/tgtdeleg` はクライアントに資格情報なしで Kerberos GSS-API ダンスを強制させるので便利）。
2. 返された TGT を krbtgt キーで復号し、PAC 属性（ユーザー、グループ、ログオン情報、SIDs、デバイスクレーム等）をパッチする。
3. 同じ krbtgt キーでチケットを再暗号化／署名し、現在のログオン セッションに注入する（`kerberos::ptt`, `Rubeus.exe ptt` 等）。
4. 必要に応じて、有効な TGT blob と対象サービスキーを使って service ticket に対して同じ処理を行い、ワイヤ上でのステルス性を保つ。

### Updated Rubeus tradecraft (2024+)

Huntress による最近の作業は、Rubeus の内部にある `diamond` アクションを近代化し、以前は golden/silver tickets のみに存在した `/ldap` と `/opsec` の改善点を移植しました。`/ldap` は AD から直接正確な PAC 属性（ユーザープロファイル、logon hours、sidHistory、ドメインポリシー）を自動入力し、`/opsec` は二段階の pre-auth シーケンスを実行して AES-only crypto を強制することで AS-REQ/AS-REP フローを Windows クライアントと見分けがつかないものにします。これにより、空白の device IDs や非現実的な有効期間などの明白な指標が大幅に減少します。
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap`（オプションの `/ldapuser` および `/ldappassword` と共に）は AD と SYSVOL を照会して、ターゲットユーザーの PAC ポリシーデータをミラーします。
- `/opsec` は Windows ライクな AS-REQ リトライを強制し、ノイズの多いフラグをゼロ化し、AES256 を使用します。
- `/tgtdeleg` は被害者の cleartext password や NTLM/AES キーに触れずに、復号可能な TGT を返します。

### Service-ticket recutting

同じ Rubeus のリフレッシュで、diamond technique を TGS blobs に適用する機能が追加されました。`diamond` に **base64-encoded TGT**（`asktgt`、`/tgtdeleg`、または以前に偽造した TGT から）、**service SPN**、および **service AES key** を与えることで、KDC に触れることなく現実的なサービスチケットを作成でき—事実上よりステルスな silver ticket になります。
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
このワークフローは、すでにサービスアカウントのキー（例：`lsadump::lsa /inject` や `secretsdump.py` でダンプしたもの）を掌握しており、新たな AS/TGS トラフィックを発生させずに、AD ポリシー、タイムライン、PAC データに完全に一致する一回限りの TGS を作成したい場合に理想的です。

### OPSEC と検出に関する注意

- 従来の検出ヒューリスティック（AS なしの TGS、10 年単位の有効期間など）は golden tickets に対しても有効ですが、diamond tickets は主に **PAC の内容やグループマッピングがあり得ないように見える場合** に表面化します。自動比較で偽造が即座に検出されないよう、すべての PAC フィールド（logon hours、user profile paths、device IDs）を埋めてください。
- **groups/RIDs を過剰に割り当てないこと**。`512`（Domain Admins）や `519`（Enterprise Admins）だけで足りるならそこで止め、ターゲットアカウントが AD の他の場所でも妥当にこれらのグループに属していることを確認してください。過剰な `ExtraSids` は明らかな手がかりです。
- Splunk の Security Content プロジェクトは、diamond tickets に関する attack-range テレメトリや、*Windows Domain Admin Impersonation Indicator* のような検出（異常な Event ID 4768/4769/4624 の連続や PAC グループの変更を相関させるもの）を配布しています。上記コマンドでそのデータセットを再生するか自前で生成することで、T1558.001 に対する SOC のカバレッジを検証でき、回避のための具体的なアラートロジックも得られます。

## 参考

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
