# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket は TGT で、**任意のユーザとして任意のサービスにアクセスする**ために使用できます。

A golden ticket は完全にオフラインで偽造され、そのドメインの krbtgt ハッシュで暗号化され、ログオンセッションに注入して使用されます。ドメインコントローラは正規に発行した TGT を追跡しないため、自身の krbtgt ハッシュで暗号化された TGT を問題なく受け入れます。

golden tickets の使用を検出する一般的な手法は 2 つあります：

- 対応する AS-REQ を持たない TGS-REQ を探す。
- Mimikatz のデフォルトである 10 年など、ばかげた値を持つ TGT を探す。

A diamond ticket は DC によって発行された正当な TGT のフィールドを修正して作成されます。具体的には TGT をリクエストし、ドメインの krbtgt ハッシュで復号してチケットの目的のフィールドを変更し、再度暗号化します。これにより、先に挙げた golden ticket の 2 つの欠点が解消されます：

- TGS-REQ には前段として AS-REQ が存在する。
- TGT は DC によって発行されているため、ドメインの Kerberos ポリシーに基づく正しい詳細をすべて備えています。これらは golden ticket でも正確に偽造可能ですが、より複雑でミスが起きやすいです。

### 要件とワークフロー

- 暗号資料: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- 正当な TGT blob: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- コンテキストデータ: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- Service keys（サービスチケットを再作成する場合のみ）: AES key of the service SPN to be impersonated.

1. AS-REQ を使って任意のコントロール下ユーザの TGT を取得します（Rubeus `/tgtdeleg` は、クライアントに資格情報なしで Kerberos GSS-API ダンスを強制させるため便利です）。
2. 返却された TGT を krbtgt キーで復号し、PAC 属性（ユーザ、グループ、ログオン情報、SIDs、デバイスクレーム等）をパッチします。
3. 同じ krbtgt キーでチケットを再暗号化/署名し、現在のログオンセッションに注入します（`kerberos::ptt`, `Rubeus.exe ptt`...）。
4. オプションで、ワイヤ上でステルス性を保つために、有効な TGT blob と対象サービスキーを供給してサービスチケットに対して同様の処理を繰り返します。

### 更新された Rubeus の手法 (2024+)

Huntress による最近の作業で、Rubeus 内の `diamond` action が近代化され、これまで golden/silver tickets のみで存在した `/ldap` と `/opsec` の改善が移植されました。`/ldap` は LDAP に問い合わせて実際の PAC コンテキストを取得し、さらに SYSVOL をマウントしてアカウント/グループ属性や Kerberos/password policy（例: `GptTmpl.inf`）を抽出します。一方 `/opsec` は、二段階の preauth 交換を行い AES-only + 現実的な KDCOptions を強制することで AS-REQ/AS-REP のフローを Windows に一致させます。これにより、PAC フィールドの欠落やポリシーと合わない有効期限などの明白な検出指標が大幅に減少します。
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) は AD と SYSVOL をクエリして、ターゲットユーザーの PAC ポリシーデータをミラーリングします。
- `/opsec` は Windows ライクな AS-REQ 再試行を強制し、ノイズの多いフラグをゼロ化し、AES256 を使用し続けます。
- `/tgtdeleg` は被害者の平文パスワードや NTLM/AES キーに触れずに、復号可能な TGT を返します。

### Service-ticket recutting

同じ Rubeus の更新により、TGS blobs に diamond technique を適用する機能が追加されました。`diamond` に **base64-encoded TGT**（`asktgt`、`/tgtdeleg`、または以前に偽造した TGT から）、**service SPN**、および **service AES key** を与えることで、KDC に触れることなく現実味のあるサービスチケットを作成できます — 実質的によりステルスな silver ticket です。
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
このワークフローは、すでにサービスアカウントのキーを掌握している（例: `lsadump::lsa /inject` や `secretsdump.py` でダンプした）場合に理想的で、新たに AS/TGS トラフィックを発生させることなく、AD のポリシー、期限、PAC データに完全に合致する単発の TGS を切りたいときに使います。

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. Instead of inventing extra SIDs, you request a U2U S4U2self ticket for a high-privilege user where the `sname` targets the low-priv requester; the KRB_TGS_REQ carries the requester's TGT in `additional-tickets` and sets `ENC-TKT-IN-SKEY`, allowing the service ticket to be decrypted with that user's key. You then extract the privileged PAC and splice it into your legitimate TGT before re-signing with the krbtgt key.

Impacket の `ticketer.py` は現在 `-impersonate` + `-request`（live KDC exchange）で sapphire をサポートしています:
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` は username または SID を受け取ります；`-request` はチケットを復号／パッチするためにライブのユーザ認証情報と krbtgt 鍵素材（AES/NTLM）を要求します。

Key OPSEC tells when using this variant:

- TGS-REQ は `ENC-TKT-IN-SKEY` と `additional-tickets`（被害者の TGT）を含みます — 通常のトラフィックでは稀です。
- `sname` はしばしば要求ユーザと同一（セルフサービスアクセス）で、Event ID 4769 は呼び出し元とターゲットが同じ SPN/ユーザとして記録されます。
- 同じクライアントコンピュータで 4768/4769 のペアが出現し、しかし CNAMES が異なる（低権限の要求者 vs. 権限を持つ PAC オーナー）ことを期待してください。

### OPSEC & detection notes

- 従来のハンター向けヒューリスティクス（AS なしの TGS、10年単位の有効期限）は golden tickets にも適用されますが、diamond tickets は主に **PAC の内容やグループマッピングがありえないように見えるとき** に表面化します。自動比較で偽造が即座に検出されないよう、すべての PAC フィールド（ログオン時間、ユーザープロファイルパス、デバイス ID など）を埋めてください。
- **グループ/RID を過剰に割り当てないこと**。もし `512`（Domain Admins）と `519`（Enterprise Admins）だけで十分ならそこで止め、対象アカウントが AD の他箇所でそれらのグループに妥当に属していることを確認してください。過剰な `ExtraSids` は明らかな手がかりです。
- Sapphire-style のスワップは U2U の指紋を残します：`ENC-TKT-IN-SKEY` + `additional-tickets` に加え、4769 の `sname` がユーザ（多くは要求者）を指し、その偽造チケットに由来する追跡の 4624 ログオンが続きます。no-AS-REQ のギャップだけを見るのではなく、これらのフィールドを相関させてください。
- Microsoft は CVE-2026-20833 のために **RC4 service ticket issuance** を段階的に廃止し始めています；KDC 上で AES-only の etypes を強制することはドメインを強化すると同時に diamond/sapphire ツール群（/opsec は既に AES を強制）とも整合します。偽造 PAC に RC4 を混在させると目立つようになっていきます。
- Splunk の Security Content プロジェクトは diamond tickets の攻撃レンジのテレメトリと、*Windows Domain Admin Impersonation Indicator* のような検出（異常な Event ID 4768/4769/4624 のシーケンスと PAC グループ変更を相関）を配布しています。そのデータセットを再生する（または上記コマンドで独自に生成する）ことで、T1558.001 に対する SOC のカバレッジ検証と回避のための具体的なアラートロジックの作成に役立ちます。

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
