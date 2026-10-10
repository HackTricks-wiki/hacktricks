# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticketと同様に**、diamond ticketは、**任意のユーザーとして任意のサービスにアクセスするために**使用できるTGTです。golden ticketは完全にオフラインで偽造され、そのドメインのkrbtgt hashで暗号化された後、使用するためにログオンセッションに渡されます。ドメインコントローラーは、正規に発行したTGTを追跡しないため、自身のkrbtgt hashで暗号化されたTGTを問題なく受け入れます。<sup>[[1]](#references)</sup>

golden ticketの使用を検出する一般的な手法は2つあります。

- 対応するAS-REQがないTGS-REQを探す。
- Mimikatzのデフォルトの10年の有効期間のような、不自然な値を持つTGTを探す。

**diamond ticket**は、**DCによって発行された正規のTGTのフィールドを変更して**作成します。これは、**TGTを要求**し、ドメインのkrbtgt hashで**復号**して、チケットの任意のフィールドを**変更**し、その後**再暗号化する**ことで実現します。これにより、golden ticketの前述した2つの欠点を克服できます。理由は次のとおりです。<sup>[[1]](#references)</sup>

- TGS-REQの前にAS-REQが存在する。
- TGTはDCによって発行されるため、ドメインのKerberosポリシーに沿った正しい詳細情報が含まれる。golden ticketでも正確に偽造できますが、より複雑で、ミスが起こりやすくなります。

### 要件とワークフロー

- **暗号素材**: TGTの復号と再署名に使用するkrbtgt AES256 key（推奨）またはNTLM hash。
- **正規のTGT blob**: `/tgtdeleg`、`asktgt`、`s4u`、またはメモリからチケットをエクスポートして取得。
- **コンテキストデータ**: 対象ユーザーのRID、グループのRID/SID、および（任意で）LDAPから取得したPAC属性。
- **サービスキー**（サービスチケットを再作成する場合のみ）: なりすますサービスSPNのAES key。

1. AS-REQで制御下にある任意のユーザーのTGTを取得する（Rubeusの`/tgtdeleg`は、資格情報なしでクライアントにKerberos GSS-APIのやり取りを実行させるため便利）。
2. 返されたTGTをkrbtgt keyで復号し、PAC属性（ユーザー、グループ、ログオン情報、SID、デバイスクレームなど）をパッチする。
3. 同じkrbtgt keyでチケットを再暗号化・署名し、現在のログオンセッションに注入する（`kerberos::ptt`、`Rubeus.exe ptt`など）。
4. 任意で、有効なTGT blobと対象サービスのkeyを指定してサービスチケットに対して同じ処理を行い、通信上のステルス性を保つ。

### 更新されたRubeusの手法（2024年以降）

Huntressによる最近の取り組みでは、これまでgolden/silver ticketにしかなかった`/ldap`と`/opsec`の改善をRubeusの`diamond`アクションに移植し、最新化しました。`/ldap`はLDAPへのクエリに加えてSYSVOLをマウントし、アカウントやグループの属性とKerberos/パスワードポリシー（例: `GptTmpl.inf`）を取得して、実際のPACコンテキストを取り込みます。一方、`/opsec`は2段階のpreauth交換を実行し、AESのみを使用して現実的なKDCOptionsを適用することで、AS-REQ/AS-REPのフローをWindowsに一致させます。これにより、PACフィールドの欠落やポリシーと一致しない有効期間など、明白な兆候を大幅に減らせます。<sup>[[3]](#references)</sup>

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

- `/ldap`（任意で `/ldapuser` と `/ldappassword` を指定）は、AD と SYSVOL を照会し、対象ユーザーの PAC ポリシーデータを複製します。
- `/opsec` は Windows 風の AS-REQ リトライを強制し、目立つフラグをゼロにして AES256 のみを使用します。
- `/tgtdeleg` は、被害者のクリアテキストパスワードや NTLM/AES キーに触れることなく、復号可能な TGT を返します。

### サービスチケットの再生成

同じ Rubeus のアップデートでは、diamond technique を TGS blob に適用する機能も追加されました。`diamond` に **base64 エンコードされた TGT**（`asktgt`、`/tgtdeleg`、または以前に偽造した TGT から取得）、**サービス SPN**、および **サービス AES キー**を渡すことで、KDC に接触することなく、本物らしいサービスチケットを生成できます。実質的には、よりステルス性の高い silver ticket です。<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

このワークフローは、サービスアカウントのキーをすでに掌握しており（例: `lsadump::lsa /inject` または `secretsdump.py` でダンプ済み）、新たな AS/TGS トラフィックを発生させずに、AD のポリシー、タイムライン、PAC データに完全に合致する TGS を一度だけ作成したい場合に最適です。<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

**sapphire ticket** と呼ばれることもある新しい手法では、Diamond の「real TGT」を基盤として、**S4U2self+U2U** を使い、特権 PAC を盗んで自身の TGT に差し込みます。SID を追加で捏造する代わりに、特権ユーザー向けの U2U S4U2self ticket を要求し、`sname` が権限の低い要求者を指すようにします。KRB_TGS_REQ には要求者の TGT を `additional-tickets` に含め、`ENC-TKT-IN-SKEY` を設定することで、そのユーザーのキーを使って service ticket を復号できるようにします。次に、特権 PAC を抽出し、krbtgt key で再署名する前に、正規の TGT に組み込みます。<sup>[[2]](#references)[[5]](#references)</sup>

Impacket の `ticketer.py` には、`-impersonate` + `-request` を使う Sapphire サポート（ライブ KDC との通信）が追加されています。<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` はユーザー名または SID を受け取り、`-request` ではチケットを復号・パッチするために、実際のユーザー認証情報と krbtgt キーマテリアル（AES/NTLM）が必要です。

この variant を使用する際の主な OPSEC 上の手がかり:<sup>[[5]](#references)</sup>

- TGS-REQ には `ENC-TKT-IN-SKEY` と `additional-tickets`（victim TGT）が含まれます。通常のトラフィックではまれです。
- `sname` は要求ユーザーと一致することがよくあります（セルフサービスアクセス）。Event ID 4769 では、呼び出し元とターゲットが同じ SPN/ユーザーとして記録されます。
- 同じクライアントコンピューターからの 4768/4769 の組み合わせが予想されますが、CNAME は異なります（低権限の要求者と、特権を持つ PAC の所有者）。

### OPSEC と検出に関する注意点

- 従来の hunter のヒューリスティック（AS なしの TGS、10 年単位の有効期間）は golden tickets にも引き続き有効ですが、diamond tickets は主に **PAC の内容やグループマッピングに不自然な点がある場合**に検出されます。自動比較で偽造がすぐに発覚しないよう、ログオン時間、ユーザープロファイルパス、デバイス ID など、PAC のすべてのフィールドを埋めてください。<sup>[[3]](#references)</sup>
- **グループ/RID を過剰に追加しないでください**。必要なのが `512`（Domain Admins）と `519`（Enterprise Admins）だけなら、それ以上は追加せず、AD 内の別の場所でもターゲットアカウントがこれらのグループに所属していることが自然に見えるようにしてください。過剰な `ExtraSids` は明らかな手がかりになります。
- Sapphire-style のスワップでは U2U の痕跡が残ります。4769 に `ENC-TKT-IN-SKEY` + `additional-tickets` と、ユーザー（多くの場合、要求者）を指す `sname` が含まれ、その後、偽造チケットを使用した 4624 のログオンが発生します。AS-REQ がないことだけを調べるのではなく、これらのフィールドを相関させてください。<sup>[[5]](#references)</sup>
- Microsoft は CVE-2026-20833 に関連して **RC4 service ticket の発行**を段階的に廃止し始めました。KDC で AES のみの etypes を強制すると、ドメインのセキュリティが強化され、diamond/sapphire tooling とも整合します（/opsec はすでに AES を強制します）。偽造 PAC に RC4 を混在させると、今後ますます目立つようになります。<sup>[[6]](#references)</sup>
- Splunk の Security Content project では、diamond tickets の attack-range telemetry に加え、*Windows Domain Admin Impersonation Indicator* などの検出ルールを配布しています。これらは、通常とは異なる Event ID 4768/4769/4624 のシーケンスと PAC のグループ変更を相関させます。このデータセットを再生する（または上記のコマンドで独自に生成する）と、T1558.001 に対する SOC の対応範囲を検証できるうえ、回避に利用できる具体的な alert logic も得られます。<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – 貴重な宝石：Kerberos 攻撃の新世代（2022）](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket：チケットを使った遊びが大好き（2023）](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kerberos Diamond Ticket の再検証（2025）](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket の攻撃データと検出ルール（2023）](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – 宝石の影の部分：Diamond & Sapphire Ticket（2025）](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – CVE-2026-20833 に関連する RC4 service ticket の強制について](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
