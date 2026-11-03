# LDAP Signing と Channel Binding のハードニング

{{#include ../../banners/hacktricks-training.md}}

## 重要な理由

LDAP relay/MITM 攻撃では、認証をドメインコントローラーに転送し、認証済みの LDAP コンテキストを取得します。[名前解決 poisoning と relay の概要](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)では、より広範な手順を説明しています。関連する次の 2 つの制御によって、こうした攻撃経路を抑制できます。

- **LDAP channel binding (CBT)** は、該当する認証を LDAPS で使用される TLS サーバー証明書／チャネルに結び付け、異なるチャネル間での relay を困難にします。
- **LDAP signing** は、SASL LDAP bind に整合性保護を要求します。機密性は追加されないため、LDAP の内容も暗号化する必要がある場合は TLS を使用してください。<sup>[[2]](#references)</sup>

**簡易的な状態確認**: `netexec ldap <dc> -u user -p pass` などのツールで、観測された signing と channel-binding のポリシーを確認できます。(signing:None) と (channel binding:Never) は制御が未設定であることを示します。ただし、relay が成功するかどうかは、取得した認証の種類、EPA の動作、アカウント権限、ターゲットプロトコル、relay 対策にも依存します。relay された principal に必要な権限がある場合、KrbRelayUp などのツールで `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み、resource-based constrained delegation (RBCD) を構成し、その委任経路を使って特権 principal を impersonate できます。<sup>[[4]](#references)</sup>

**Server 2025 DC** では新しい GPO (**LDAP server signing requirements Enforcement**) が導入され、**Not Configured** のままにすると、デフォルトで **Require Signing** が適用されます。適用を回避するには、このポリシーを明示的に **Disabled** に設定する必要があります。<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS のみ)

- **要件**:
  - CVE-2017-8563 のパッチ (2017) により、Extended Protection for Authentication のサポートが追加されます。<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) により、LDAPS CBT の「what-if」テレメトリが追加されます。<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (デフォルト、CBT なし)
  - `When Supported` (部分的な適用: CBT 対応クライアントには有効な token の提示を要求します。CBT 非対応クライアントは引き続き bind できます。監査イベントも出力されます)
  - `Always` (適用: 有効な CBT のない LDAPS bind を拒否します)<sup>[[1]](#references)</sup>
- **監査**: **When Supported** に設定すると、次のイベントが確認できます:
  - **3074** – 適用時に CBT 検証に失敗していた LDAPS bind。
  - **3075** – CBT データがなく、適用時に拒否されていた LDAPS bind。
  - (古いビルドでは、イベント **3039** も引き続き CBT の失敗を示します。)<sup>[[1]](#references)[[2]](#references)</sup>
- **適用**: LDAPS クライアントが CBT を送信するようになったら **Always** に設定します。この設定が有効なのは **LDAPS** のみで、raw 389 には適用されません。<sup>[[1]](#references)</sup>

`When Supported` は監査専用ではありません。CBT 対応クライアントの CBT を検証しつつ、CBT 非対応クライアントは許可します。[Microsoft のポリシーリファレンス](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)では、バージョンによって異なるデフォルト値が説明されています。LDAP signing は LDAP/389 上の該当する bind に適用され、channel binding は TLS で保護された LDAP 認証に適用されます。


## LDAP Signing

- **クライアント GPO**: `Network security: LDAP client signing requirements` = `Require signing` (最新の Windows でのデフォルトである `Negotiate signing` とは異なります)。<sup>[[1]](#references)</sup>
- **DC GPO**:
  - レガシー: `Domain controller: LDAP server signing requirements` = `Require signing` (デフォルトは `None`)。<sup>[[2]](#references)</sup>
  - **Server 2025**: レガシーポリシーは `None` のままにして、`LDAP server signing requirements Enforcement` = `Enabled` に設定します (Not Configured ではデフォルトで適用されます。適用を回避するには `Disabled` に設定します)。<sup>[[1]](#references)</sup>
- **互換性**: simple bind または署名なしの SASL bind を使用する Windows 以外のアプライアンスやアプリケーションを洗い出します。Microsoft はサポート対象の Windows バージョンでの対応を文書化しています。レガシークライアントとの互換性に関する説明は、XP のバージョンしきい値に単純化せず、実際のクライアントスタックに照らして確認してください。<sup>[[2]](#references)</sup>

## Relay 経路と署名付き SASL の再認証

**signing のみ**が必須の場合、channel binding が適用されていなければ、LDAPS への relay は依然として成功する可能性があります。TLS がトランスポートの整合性を提供するためです。**channel binding のみ**が必須の場合、通常の LDAP には bind できる TLS チャネルがありません。relay された identity に必要な権限があれば、relay は TCP 389 で認証し、その後、TLS が必要な操作に StartTLS を使用できます。両方を適用すれば、こうした一般的な代替経路を塞げますが、未パッチのドメインコントローラーでは次の脆弱性を防げませんでした。<sup>[[5]](#references)</sup>

### Relay された Bind の後に LDAP 操作を重ねる

影響を受ける Windows Server 2016–2025 ドメインコントローラーでは、まず、TCP 389 上で identity X として **署名付き NTLM SASL LDAP 接続**を確立します。セッションキーが分かっている認証情報を使うか、許可される場合は匿名 NTLM SASL コンテキストを使用します。identity Y に **SMB 経由で** relay への認証を強制します。Y の NTLM NEGOTIATE と DC の CHALLENGE を、X の既存 LDAP 接続上の GSS-SPNEGO Bind request を通じて転送します。Windows SMB クライアントは `NTLMSSP_NEGOTIATE_SIGN` を設定するため、結果として署名付き SASL レイヤーを必要とする LDAP bind になります。HTTP/WebDAV 起点のやり取りでは通常このフラグがないため、ここでは代用できません。<sup>[[5]](#references)</sup>

Y が NTLM AUTHENTICATE を送信したら、**2 つの異なる LDAP メッセージを 1 つの length-prefixed SASL record に**含めます。まずその応答を含む BindRequest、続いて ModifyRequest を入れます。X の既知のキーで record 全体に署名します。脆弱な DC は X のキーで record を検証し、Bind を完了して接続の認可 identity を Y に切り替えた後、record を Y のキーでも再検証せずに残りの ModifyRequest を Y として実行します。これは Y のパスワードやセッションキーを漏えいさせるものではなく、後続の record に X の署名を使うと失敗します。`msDS-AllowedToActOnBehalfOfOtherIdentity` への RBCD 書き込みや、`msDS-KeyCredentialLink` への shadow credential 書き込みには、Y がターゲットオブジェクトに対する権限を持っている必要があります。[RBCD](resource-based-constrained-delegation.md)、[shadow credentials](acl-persistence-abuse/shadow-credentials.md)、および relay された DC のマシンアカウントについては [DCSync](dcsync.md) を参照してください。<sup>[[5]](#references)</sup>

これは **plain LDAP** の bypass であり、LDAPS の channel-binding bypass ではありません。LDAPS では TLS が接続を保護し、この record stacking 経路に必要な X のキーを使う NTLM SASL signing layer は Windows によって確立されません。TCP 389 が利用できない場合、この手法を TCP 636 にそのまま適用することはできません。2026 年 10 月のセキュリティ更新では、Bind によって接続 identity が切り替わった後に残りのデータを破棄することで、同じ record 内の操作を防止します。<sup>[[5]](#references)</sup> KB5126646 は Windows Server 2025 用の更新プログラムです。他の影響を受ける Server リリースには、それぞれ異なる KB 番号があります。<sup>[[7]](#references)</sup>

研究者が公開した [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) は、このワークフロー向けに変更された `ntlmrelayx.py` をラップします。実行には、**SMB** の coercion 元、LDAP signing/security-context API を公開するバージョンに固定された Impacket ツリー (PyPI の Impacket 0.13.1 は不十分)、および最初の署名付き bind 用に攻撃者が制御するアカウントが必要です。RBCD 書き込みでは、対象オブジェクトの DN と、制御下の委任コンピューターの SID を指定します。別の許可された書き込みでは、`-attribute` と `-value` または `-value-hex` を使用します。ツールによる独立した署名付き read-back で結果を確認してください。relay 側の `FAILED` メッセージだけで ModifyRequest が失敗したと判断しないでください。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

SMB authentication は別途トリガーしてください。coercion の手段の一つについては[privileged NTLM authentication の強制](printers-spooler-service-abuse.md)を、その他の手段については[relay の概要](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を参照してください。ツールのコマンドと実装は、そのリポジトリに記載されています。<sup>[[6]](#references)</sup>

## 監査優先の段階的導入（推奨：約30日）

1. 各 DC で LDAP インターフェース診断を有効にし、署名なしの bind をログに記録します（Event **2889**）：<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. DC GPO の `LDAP server channel binding token requirements` を **When Supported** に設定し、部分的な CBT 適用とテレメトリ収集を行います。事前にレガシークライアントとの互換性を確認してください。<sup>[[1]](#references)</sup>
3. Directory Service イベントを監視します。<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – 署名なし／署名なしを許可する bind（署名要件に準拠していない）。
   - **3074/3075** – 失敗する、または CBT が欠落する LDAPS bind（2019/2022 では KB4520412 と上記の手順 2 が必要）。
4. 個別に変更して適用します。<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always**（DC）。
   - `LDAP client signing requirements` = **Require signing**（クライアント）。
   - `LDAP server signing requirements` = **Require signing**（DC）、**または**（Server 2025）`LDAP server signing requirements Enforcement` = **Enabled**。



## References

- [1] [TrustedSec - LDAP Channel Binding と LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding と signing の要件](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay の緩和策アップデート](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno（LDAP signing 無効 → Kerberos relay → RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – 署名、暗号化、リレー：NTLM 方式](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo の proof of concept](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Windows Server リリース情報](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
