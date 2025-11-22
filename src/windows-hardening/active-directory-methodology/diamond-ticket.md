# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticket のように**、diamond ticket は任意のユーザーとして**任意のサービスにアクセスする**ために使用できる TGT です。golden ticket は完全にオフラインで偽造され、当該ドメインの krbtgt hash で暗号化されてからログオンセッションに渡されて使用されます。ドメインコントローラーは実際に発行した TGT を追跡しないため、自ドメインの krbtgt hash で暗号化された TGT を喜んで受け入れます。

golden ticket の使用を検出する一般的な手法は二つあります:

- 対応する AS-REQ がない TGS-REQ を探す。
- Mimikatz のデフォルトの10年の有効期間のような、不自然な値を持つ TGT を探す。

diamond ticket は、DC によって発行された正規の TGT のフィールドを修正することで作成されます。これは TGT をリクエストし、その TGT をドメインの krbtgt hash で復号してチケットの必要なフィールドを修正し、再度暗号化することで実現します。これにより golden ticket の前述の二つの欠点を克服できます。理由は以下のとおりです:

- TGS-REQ には先行する AS-REQ が存在します。
- TGT が DC によって発行されているため、ドメインの Kerberos ポリシーに基づく正しい詳細情報をすべて含んでいます。これらは golden ticket でも正確に偽造可能ですが、より複雑でミスが生じやすくなります。

### 要件 & ワークフロー

- **Cryptographic material**: krbtgt AES256 key（推奨）または NTLM hash — TGT を復号し再署名するために必要です。
- **Legitimate TGT blob**: `/tgtdeleg`、`asktgt`、`s4u` で取得するか、メモリからチケットをエクスポートして得ます。
- **Context data**: 対象ユーザーの RID、グループの RIDs/SIDs、（任意で）LDAP に由来する PAC 属性。
- **Service keys**（service ticket を再作成する予定がある場合のみ）: 代行するサービス SPN の AES key。

1. 管理下の任意のユーザーの TGT を AS-REQ 経由で取得します（Rubeus の `/tgtdeleg` は、クライアントを資格情報なしで Kerberos GSS-API ダンスを実行させるため便利です）。
2. 返却された TGT を krbtgt key で復号し、PAC 属性（ユーザー、グループ、ログオン情報、SIDs、デバイスクレームなど）を修正します。
3. 同じ krbtgt key でチケットを再暗号化／署名し、現在のログオンセッションに注入します（`kerberos::ptt`、`Rubeus.exe ptt`...）。
4. オプションで、有線上での痕跡を残さないために、有効な TGT blob とターゲットサービスキーを供給して同様の手順を service ticket に対して繰り返します。

### Updated Rubeus tradecraft (2024+)

Huntress による最近の作業で、Rubeus 内の `diamond` アクションが近代化され、以前は golden/silver tickets にしか存在しなかった `/ldap` と `/opsec` の改善が取り込まれました。`/ldap` は現在 AD から正確な PAC 属性（ユーザープロファイル、ログオン時間、sidHistory、ドメインポリシー）を自動で入力し、`/opsec` は二段階の事前認証シーケンスを実行し AES-only crypto を強制することで AS-REQ/AS-REP のフローを Windows クライアントと区別がつかないものにします。これにより、空のデバイス ID や現実的でない有効期間といった明白な指標が劇的に減少します。
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) は AD と SYSVOL を照会して対象ユーザーの PAC ポリシーのデータをミラーリングします。
- `/opsec` は Windows ライクな AS-REQ リトライを強制し、ノイズの多いフラグをゼロ化し、AES256 を使用します。
- `/tgtdeleg` は被害者の cleartext password や NTLM/AES key に触れずに、復号可能な TGT を返します。

### サービスチケットの再生成

同じ Rubeus の刷新で、diamond technique を TGS blobs に適用する機能も追加されました。`diamond` に **base64-encoded TGT**（`asktgt`、`/tgtdeleg`、または以前に偽造した TGT から）、**service SPN**、および **service AES key** を与えることで、KDC に触れずに現実味のあるサービスチケットを生成できます — 実質的によりステルスな silver ticket。
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
このワークフローは、既にサービスアカウントのキーを掌握している（例: `lsadump::lsa /inject` や `secretsdump.py` でダンプした）場合に理想的です。新たに AS/TGS トラフィックを発生させることなく、AD ポリシー、タイムライン、PAC データに完全に一致する一回限りの TGS を作成したいときに向いています。

### OPSEC & 検出に関する注意事項

- 伝統的なハンターのヒューリスティクス（AS なしの TGS、10年単位の有効期間）は golden tickets にも依然として当てはまりますが、diamond tickets は主に **PAC の内容やグループマッピングが不可能に見える** 場合に表面化します。自動比較で即座に偽造と判定されないよう、すべての PAC フィールド（ログオン時間、ユーザープロファイルパス、デバイス ID）を埋めてください。
- **groups/RIDs を過剰に割り当てないでください**。必要なのが `512` (Domain Admins) と `519` (Enterprise Admins) のみであればそこで止め、対象アカウントが AD の他所でそれらのグループに存在することがもっともらしく見えるか確認してください。過剰な `ExtraSids` はバレる原因です。
- Splunk の Security Content プロジェクトは、diamond tickets 用の attack-range テレメトリと、*Windows Domain Admin Impersonation Indicator* のような検出ルールを配布しています。これらは異常な Event ID 4768/4769/4624 の連続や PAC のグループ変更を相関させます。そのデータセットを再生する（または上記コマンドで自分で生成する）ことで、T1558.001 に対する SOC のカバレッジを検証し、回避のための具体的なアラートロジックを得ることができます。

## 参考

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
