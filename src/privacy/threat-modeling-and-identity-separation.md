# Threat Modeling & Identity Separation

{{#include ../banners/hacktricks-training.md}}

最も一般的な匿名性の失敗は、暗号が破られることではありません。それは**linkage**です。つまり、1つの識別子、タイミングパターン、デバイス、アカウント、支払い、ファイル、または人間の習慣によって、本来分離されるべき2つのコンテキストが結び付けられることです。

## プライバシー脅威モデルを構築する

EFFの6つの質問によるセキュリティ計画は、有力な基盤です。何を保護する必要があるか、誰から保護するか、失敗の影響と可能性、利用できる労力、そして支援してくれる仲間を明確にします。<sup>[[1]](#references)</sup> 小さな表を使って、これを実際に運用できる形にします。

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| クライアントの調査 | ISP | 宛先およびタイミングのメタデータ | 自宅の加入者記録 | Tor Browser | Torの使用が可視化される。end-to-end correlation |
| 仮名アカウント | Platform | IP、ブラウザ、recovery data | 再利用された電話番号/email/写真 | 専用コンテキストとalias | 文章およびsocial graphによる相関 |
| オンライン購入 | Merchant | アカウント、配送、tokenized card | 住所およびアカウント履歴 | Guest checkout、最小限の入力項目、virtual card | Issuerおよびcarrierが記録を保持 |
| Red-team traffic | Target/client | Source IPおよび挙動 | Provider/engagement records | 専用の承認済みegress | escalation時には意図的に帰属可能 |

場所、provider、デバイス、相手、または結果が変わるたびに表を見直します。

## linkability graphを描く

各identityを別々のノードとして扱います。共有されている属性ごとにedgeを追加します。

- emailまたはrecovery address;
- 電話番号またはcontact-book upload;
- username、avatar、写真、bio、またはwriting/code style;
- password、passkey-sync account、またはrecovery question;
- デバイス、advertising ID、browser profile、cookies、fonts、またはextensions;
- IP address、time zone、言語、スケジュール、または同時オンライン状態;
- bank card、exchange account、wallet cluster、shipping address、またはloyalty program;
- document author fields、EXIF location、printer marks、またはcloud-share owner;
- 同僚、group membership、social graph。

edgeは必ずしも致命的ではありませんが、どのobserverが接続を成立させられるかを示します。EFFは、電話番号、email address、再利用された写真によってprofilesがリンクされる可能性を明確に警告しています。<sup>[[2]](#references)</sup>

## compartmentを段階的に作成する

1. **コンテキストと禁止するリンクを定義する。** 例: `client-red-2026`。個人用email、home browser profiles、個人用payment methods、無関係なclientsから分離する。
2. **isolation boundaryを選択する。** 強度の低い順に、separate browser profile → separate OS account → separate VM/qube → dedicated device。別のtabやprivate windowはsecurity boundaryではありません。
3. **そのboundary内で新しい識別子を作成する。** コンテキスト専用のemail/alias、username、password-manager vaultまたはcollection、authentication keysを使用します。providerからのunlinkabilityが重要な場合、個人用recovery channelを追加しないでください。
4. **1つのnetwork policyを選択する。** そのコンテキストで常にclient VPN、engagement VPS、trusted VPN、Torのどれを使用するか決定します。可能な場合はfail-closed routingを強制します。
5. **payment policyを選択する。** payment methodはobserver modelに適合させる必要があります。virtual cardはmerchantからPANを隠せても、issuerにはcustomerを特定させます。
6. **data-transfer rulesを設定する。** 範囲を限定した意図的なtransferを優先します。clipboard、shared folders、USB devices、cloud sync、printers、screenshotsは、ブリッジになる可能性があるものとして扱います。
7. **作成日とteardown日を記録する。** 契約、税務、complianceのために保持すべき証拠と、期限切れにすべき一時データを定義します。
8. **使用前にリンクをテストする。** account settings、recovery fields、public profile、IP/DNS、browser state、file metadata、provider dashboardsを確認します。

{% hint style="warning" %}
サービスまたは法律が正確な本人情報を要求する場合、そのidentity informationを捏造しないでください。privacy compartmentは、データの最小化と分離のためのものであり、identity fraudやcustomer due diligenceの回避のためのものではありません。
{% endhint %}

## Endpointとアカウントのbaseline

- サポート対象のhardwareを使用し、OS、browser、wallet、firmwareのupdatesを速やかにインストールします。
- device encryptionを有効にし、強力なdevice passcodeを使用します。Encryption at restは、電源オフのdeviceを紛失または押収された場合には役立ちますが、malwareやunlock済みのsessionがデータを読み取れる状態では役立ちません。<sup>[[3]](#references)</sup>
- password managerで、固有のランダム生成passwordsを使用します。
- threat modelでrecovery/sync modelが許容される場合は、WebAuthn/passkeysやhardware security keysなどのphishing-resistant authenticationを優先します。NISTは、手動入力のOTPsは、攻撃者がそれらをrelayできるためphishing-resistantではないと説明しています。<sup>[[4]](#references)</sup>
- recovery codesをofflineで保管し、endpointから分離します。synced passkey accountによって、本来分離すべきidentityが結合されないか確認します。
- 不要なlocation、contacts、microphone、camera、Bluetooth、advertising-ID、background permissionsを無効にします。
- personal cloud sync、browser sync、password-manager accounts、app storesをhigh-separation contextに混在させないでください。

## Browser privacy

Browser fingerprintingは、観測可能なconfiguration、device、environment、behaviorを使ってuserを識別または相関させます。cookiesの削除やIP addressesの変更だけでは確実に防げず、W3Cは、広く展開された手段によって完全に技術的排除を行うことは現実的でないとしています。<sup>[[5]](#references)</sup>

通常のprivacy対策:

1. HTTPS-only modeと強力なtracking protectionを備えた、保守されているbrowserを使用します。
2. third-party trackingをブロックし、対応している場合はstateをpartitionします。
3. 本当に分離されたcontextsには、別々のbrowser profilesを使用します。
4. 不要なpermissionsを無効にし、定めたスケジュールでsite dataを消去します。
5. 無関係なsensitive researchを行っている間に、identity-rich accountsへloginすることを避けます。

Web anonymityには、**Tor Browserをstandard configurationで使用**します。通常のbrowserをTor経由でproxyしないでください。Tor Projectは、通常のbrowsersがDNS/WebRTC、persistent state、fonts、plugins、fingerprint differencesを通じてleakする可能性があると警告しています。<sup>[[6]](#references)</sup> 追加のextensions、 unusual window sizes、custom fonts、browserを目立たせるpreferencesは避けます。<sup>[[7]](#references)</sup>

## Communicationsとmetadata

Metadataには、message contentがencryptedであっても、sender、recipient、time、location、その他のcontextが含まれます。<sup>[[8]](#references)</sup>

- 実用上可能な場合は、server-side metadataを最小化し、open protocols/clientsを使用するend-to-end-encrypted toolsを優先します。
- 独立したchannelまたは対面でsensitive contactsを確認します。Signal safety numbersは、この確認のために設計されています。<sup>[[9]](#references)</sup>
- Signal usernamesを使えばphone numberを共有せずにcontactを開始できますが、登録には依然としてphone numberが必要です。phone-number visibility/discoverabilityは意図的に設定してください。<sup>[[9]](#references)</sup>
- Disappearing messagesは保持されるcopiesを減らしますが、recipientsはcontentを撮影、コピー、forward、archiveできます。
- Emailは通常、routing metadataを公開します。privacy-focused providersであっても、相手側が通常のemailを使用している場合、双方が互換性のあるE2EE methodを使用しない限りmessageをend-to-end encryptedにはできません。例えばProtonは、他のprovidersへの通常のmailではTLSが使用され、受信側providerから読み取り可能なままであると説明しています。<sup>[[10]](#references)</sup>
- address booksを分離し、pseudonymous accountに個人のcontactsをuploadしないでください。

## Files、photos、authorshop

Tailsは、photographsにcameraおよびlocation dataが含まれる可能性があり、office documentsにはauthorおよびcreation-time fieldsが含まれる可能性があると警告しています。<sup>[[11]](#references)</sup>

共有する前に:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
その後、クリーニング済みのコピーを隔離された viewer で再び開き、以下を確認します。

- document properties、comments、tracked changes、hidden sheets/slides、thumbnails、attachments；
- EXIF/XMP/IPTC、GPS、timestamps、device/software names、unique IDs；
- 見える反射、landmarks、screen contents、voices、faces、background sounds；
- filename、archive paths、cloud-share owner、signing certificate、revision history。

Sanitization によって evidence や authenticity が損なわれる可能性があります。chain of custody または後日の verification が重要な場合は、encrypted original を保持してください。Stylometry や coding style によって authorship が結び付けられる場合もあります。metadata の除去によって human style が変わることはありません。

## Common failure patterns

- “anonymous” connection を通じて personal account にログインする。
- recovery phone、avatar、username、public key、wallet、または donation address を再利用する。
- 相関する contexts から、2つの identities を同時に運用する。
- personal cloud clipboard または shared folder を通じて text/files をコピーする。
- 特徴的な Tor Browser extensions をインストールしたり、多数の defaults を変更したりする。
- “no logs” という主張を、何が、どのくらいの期間、どの subcontractors によって logging されるのかを理解せずに信用する。
- secondary phone が personal phone と並行して移動しているにもかかわらず、anonymous だと考える。EFF は、cellular location と co-travel によって devices を相関付けられると指摘しています。<sup>[[3]](#references)</sup>
- encryption を deletion とみなす。endpoints や recipients が plaintext を保持している可能性があります。

## Verification checklist

- [ ] context に personal recovery address、phone、sync account、または意図的に受け入れたものを除く reused media が存在しない。
- [ ] intended network path が有効で、fails closed する。
- [ ] browser/device time zone、locale、extensions、permissions が plan と一致している。
- [ ] compartment 内で personal accounts が開かれていない。
- [ ] files が inspected および sanitized され、originals は別途扱われている。
- [ ] contacts が second channel を通じて authenticated されている。
- [ ] provider-visible metadata と retention period を理解している。
- [ ] teardown、evidence retention、account-recovery procedures が document されている。

## References

- [1] [EFF Surveillance Self-Defense — セキュリティ計画](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks で自分を守る](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Protest への参加](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication と Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications における Browser Fingerprinting の Mitigating](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — 他の browsers と Tor を使用する](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser の Plugins と add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata が重要な理由](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy と Usernames：さらに詳しく](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail 内で encrypted されるもの](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings：Tails は safe だが magic ではない](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
