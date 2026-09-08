# Privacy-Preserving Communications and Sharing

{{#include ../banners/hacktricks-training.md}}

End-to-end encryptionはコンテンツを保護します。しかし、アカウント、電話番号、contact graph、IPアドレス、push token、notification preview、タイミング、ファイルメタデータ、受信者の行動を自動的に隠すわけではありません。どのメタデータを削除し、どの観測者を介在させるかを基準にツールを選択してください。

## 通信モデルの比較

| ツール/モデル | 有用な特性 | 残る観測者と制限 |
|---|---|---|
| Signal | 成熟したE2EE。ユーザー名で電話番号を共有せずに連絡を開始可能。sealed senderによりサービスメタデータを削減 | 登録には電話番号が必要。service、push provider、contacts、endpointsには一部の観測情報が残る |
| SimpleX | グローバルなユーザー識別子なし。連絡先ごとのキュー。Tor transportは任意 | Relayのタイミング/transport、push service、invitations、endpoints。より新しく、小規模なecosystem |
| Briar | 直接同期。オンライン時はTor、オフライン時はBluetooth/Wi-Fi。中央のメッセージストアなし | Contactsとendpoints。ローカル無線の観測者。Android中心。双方が利用可能であるか、Mailboxを使用する必要がある |
| OnionShare | 一時的なonion serviceを介した直接のファイル送受信/chat/site。storage providerなし | Senderのcomputerがserviceになる。linkの保有者はアクセスを知る。タイミングとendpointsは残る |
| `age` encrypted file | transportから独立した単純なrecipient-key encryption | Transportはsender/recipient、タイミング、サイズを把握する。ファイル名/archiveメタデータとendpointsは残る |
| 通常のemail + TLS | Server-to-serverのchannel encryption | 通常、双方のmail providersがコンテンツを読め、routing/accountメタデータを保持できる |

## Signal: 番号を開示しないプライベートな連絡

Signal usernamesを使用すると、ユーザーの電話番号を新しい連絡先に明らかにせずにchatを開始できますが、登録には電話番号が必要です。<sup>[[1]](#references)</sup> Sealed senderは段階的なメタデータ保護であり、すべてのIP/タイミング相関に対する耐性ではありません。<sup>[[2]](#references)</sup>

### ワークフロー

1. 公式のapp store/projectからSignalをインストールし、最初にOSを更新します。
2. 合法的に使用する権利を持つ番号で登録します。レンタルSMS activation、他人の番号、虚偽の身元で取得したprovider accountは使用しないでください。
3. **Settings → Privacy → Phone Number**で、threat modelに応じて、誰が番号を見られるか、また番号でaccountを検索できる人を設定します。
4. 新しいcontactの発見用にusernameを作成します。その正確なlink/QRを、すでに認証済みのchannelを通じて共有します。usernameは変更可能で、profile nameではありません。
5. 利便性がlinkageに見合わない場合はcontact upload/permissionsを無効にし、platformが対応している場合は手動でcontactsを追加します。
6. 機密性の高いコンテンツを送る前に、contact detailsを開き、second channelまたは対面でsafety number/QRを比較します。
7. linked devices、registration lock/PIN、notification previews、screen security、call relaying、disappearing-message defaults、backup behaviorを確認します。
8. 機密性のないtest messageを送り、通話します。双方でlock-screen、desktop、wearable、cloud-notificationの痕跡を確認します。
9. 変更されたsafety numberや予期しないlinked deviceは、自動的に無視するalertではなく、調査すべき事象として扱います。

pseudonymousなprofile photo、bio、group membership、scheduleを、個人を特定できるSignal contextと混在させないでください。

## SimpleX: グローバルな識別子を使用しない連絡先ごとの接続

SimpleXは一方向のqueuesを通じてメッセージをroutingし、network-wideなuser identifierを割り当てません。ただし、独自のpolicyではtransport sessions、temporary server data、push-notificationのトレードオフ、endpointの責任についても記載されています。<sup>[[3]](#references)</sup>

### ワークフロー

1. 維持管理されているclientを公式のproject/storeからダウンロードし、publisherを検証します。identityを混在させてはならない場合は、専用のOS/app profileを使用します。
2. context固有のdisplay nameとimageを使用して**local** profileを作成します。backupなしでappを削除すると、profileとconnectionsを失う可能性があります。
3. 初回起動時にnotification modeを意図的に選択します。Instant mobile pushにより、Apple/Google infrastructureに追加のメタデータが公開される可能性があります。
4. 1人のcontact用にone-time invitation linkを作成します。認証済みchannelを通じて転送します。live invitationを取得した者は誰でも、それを使用しようとする可能性があります。
5. 接続後、contact detailsを開き、対面または独立した検証済みchannelでsecurity codeを比較します。<sup>[[4]](#references)</sup>
6. 対応している場合は、同じprofileを無関係な複数のgroupで再利用する代わりに、groupごとのincognito profileを使用します。
7. local network/serverからdirect IPを見られないように、clientが対応するTor transportを設定します。変更後にconnectionを確認し、対応していないsystem proxyを強制しないでください。
8. delivery receipts、link previews、calls、automatic downloads、database export/backupを確認します。それぞれがメタデータまたはendpoint exposureを変化させます。
9. live profile stateを重複実行せず、予備の隔離されたdeviceでrecoveryをテストします。projectは、同時に存在するcopyがconversationsを妨害する可能性があると警告しています。

グローバルなidentifierがないからといって、contactがcontent、profile reuse、invitation delivery、タイミング、social graphを通じてユーザーを特定できなくなるわけではありません。

## Briar: 直接的で妨害に強いメッセージング

Briarはdevice間で直接同期し、オンライン時はTorを、ローカルで障害が発生している場合はBluetooth/Wi-Fiを使用します。公式のthreat modelは短距離無線に対する攻撃者の監視を限定的なものと想定しているため、local wirelessは不可視ではありません。<sup>[[5]](#references)</sup>

### ワークフロー

1. 公式のBriar distributionからインストールし、package sourceを検証します。最新のsecurity updatesが適用された対応済みAndroid deviceを使用します。
2. 固有のcontext nicknameと強力なpasswordでlocal accountを作成します。password-reset pathはないため、unlock secretを復元できることをテストします。
3. 可能な場合は、互いのQR codeをスキャンして対面でcontactsを追加します。これによりcontactが認証され、相関可能なchannelを通じてlinkを送信せずに済みます。
4. connectivity settingsで必要なtransportのみを有効にします。Tor/Internet、Wi-Fi、Bluetoothのいずれか、または複数を選択します。不要なlocal radiosは無効にします。
5. 非同期deliveryには、専用の電源接続されたdevice上でBriar Mailboxを評価します。message serverと同様に、inventoryを作成し物理的に保護します。
6. Internetが利用可能な状態で無害なtestを送信し、その後、所有者が認可した場所でInternetを無効にして、計画した障害時の経路をテストします。
7. Android backups、notification previews、screenshots、exported contentを確認します。endpointがunlockまたはcompromiseされた場合、local encrypted storageも公開されます。
8. 紛失したcontacts/devicesを削除し、物理的な管理権限またはaccount passwordが侵害された場合はcontext全体を廃止します。

## OnionShare: 直接的な一時転送

OnionShareはsender/receiverのcomputer上でonion serviceを実行します。ファイルはstorage providerにuploadされず、trafficはTor内部でend-to-end encryptedされます。<sup>[[6]](#references)</sup> 完全なonion URLはbearer capabilityであり、保護する必要があります。

### GUI file-sharingワークフロー

1. 公式の署名済みdistributionからOnionShareをインストールし、recipient側にはTor Browserをインストールします。
2. ファイルの**sanitized copies**を専用のstaging directoryに置きます。OnionShareに個人のhome directoryを指定しないでください。
3. **Share Files**を開き、staged filesのみを追加します。private key/access protectionは有効のままにし、recipientが1人の場合は**Stop sharing after files have been sent**を有効にします。
4. sharingを開始し、完全なonion URLをすでに認証済みのE2EE channelを通じて送信します。email、issue trackers、public chatsには貼り付けないでください。
5. recipientはTor BrowserでURLを開き、senderとexpected filenames/sizeを確認してからdownloadします。
6. ファイル自体がsecurity boundaryとなる場合は、integrityのために、事前に合意した、または別途配信したSHA-256 digestを双方で比較します。
7. download後にOnionShareが停止したことを確認します。停止していない場合は手動で停止し、applicationを閉じます。
8. retention policyに従ってstaged copyを削除し、意図しないfilename disclosureがないかOnionShareのhistory/log settingsを確認します。

### CLIワークフロー

公式CLIはpositional argumentsとしてfilesを受け付け、デフォルトでは1回のcompleted shareの後に停止します。公式CLI/Torがインストールされたhostでは:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
結果の完全な URL は安全に伝達してください。脅威モデル上、結果として生じる露出が明示的に必要でない限り、`--public`、`--no-autostop-sharing`、詳細なファイル名ログ、または永続化を追加しないでください。<sup>[[7]](#references)</sup>

受信したドキュメントは敵対的なものとして扱ってください。identity-bearing host 上ではなく、使い捨て VM／Dangerzone-style renderer で開いてください。

## `age` でファイルを個別に暗号化する

ストレージ／メールプロバイダーにオブジェクトを見られる可能性がある場合、転送手段に依存しない暗号化が役立ちます。ただし、送信者、受信者、サイズ、タイミング、ファイル名を隠すことはできません。これらは別途処理する必要があります。

### 受信者のセットアップ
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
公開受信者文字列を別のチャネルで認証します。その後、送信者は次を実行します：
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
受信者は新しいパスに復号します：
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
公式 CLI は、`-o` が既存の出力を上書きすることを警告しているため、新しいディレクトリを使用し、移動する前に digest/content を検証してください。<sup>[[8]](#references)</sup> ciphertext と一緒に identity file を送信しないでください。

## 再現可能な file-sanitization pipeline

Metadata の除去方法は format 固有です。authenticity、forensics、または chain of custody が重要な場合は、暗号化された original を保持し、copy に対して操作してください。

### JPEG の例
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
これは ExifTool のより安全な JPEG ガイダンスに従ったものです。すべてのタグを無差別に削除すると、色の情報まで削除される可能性があります。<sup>[[9]](#references)</sup> その後、顔、反射、画面、ランドマーク、固有の損傷やノイズのパターンがないか、ピクセルを目視で検査します。

### Office/PDF ワークフロー

1. 編集可能なオリジナルは暗号化し、公開環境から切り離してオフラインで保管します。
2. 作成アプリケーションで、コメント、変更履歴、非表示のスライドやシート、埋め込みファイル、個人用テンプレート、ドキュメントのプロパティを削除します。
3. 専用のクリーンなプロファイルから新しい PDF をエクスポートします。クラウドプリンターに「印刷」しないでください。
4. フォーマット対応ツールと、使い捨てのビジュアルレンダラーの両方で検査します。
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. レンダリングされた出力で、名前、パス、メールアドレス、リビジョンテキストを検索します。Rasterization によってアクティブな構造を除去できる場合がありますが、アクセシビリティや検索性が損なわれ、表示されるコンテンツや文体は除去されません。
6. 最終 artifact を hash 化し、そのコピー**のみ**を publication compartment 経由で転送します。

## Privacy Pass: service designers 向けの匿名 authorization

Privacy Pass は token の**発行**と**redeem**を分離します。origin は、client が issuer に承認された token を保有していることを知ることはできますが、client が具体的にどの発行処理を行ったかを知ることはできません。token の再利用、固有の metadata、タイミング、または collusion によって、linkability が再び生じる可能性があります。<sup>[[10]](#references)</sup>

安全な deployment パターン:

1. token が証明する statement（例: rate-limit の eligibility）を定義し、隠れた global identity は定義しません。
2. 標準化された architecture と issuance protocol を使用し、blind-signature cryptography をゼロから実装しないでください。
3. 必要な property がそれを要求する場合、issuer/attester と origin の administration を分離します。
4. public/private token metadata を最小限にし、anonymity set が十分に大きいことを確認します。
5. 対応している場合は使用前に batch 発行を行い、発行時刻と redeem 時刻が単純に一致しないようにします。
6. 各 token は一度だけ redeem し、origin-bound challenge を検証して、期限切れの token state を削除します。
7. cookies、IP logging、application accounts によって token の privacy property がひそかに無効化されないようにします。
8. timing、metadata、または固有の error を使って、issuer と origin の logs が管理下の発行イベントと redeem イベントを join できるかテストします。

Privacy Pass は application feature であり、ユーザーが任意の account に後付けできるものではありません。

## Communications verification checklist

- [ ] Contact/invitation/key が独立して authenticated されている。
- [ ] Phone number、username、profile、group、contact-upload の exposure を把握している。
- [ ] 直接 IP、relay、Tor、push-provider、local-radio の observers を列挙している。
- [ ] Notification previews、wearables、linked desktops、backups をテストしている。
- [ ] Files を sanitized し、必要に応じて encrypted 化し、disposable context で開いた。
- [ ] Recovery が、無関係な identities を bridge せずに機能する。
- [ ] Logs、history、temporary share services に shutdown/retention rule がある。

## References

- [1] [Signal — Phone Number Privacy と Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy と Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy と security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — 仕組み](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage と CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — 公式 CLI と usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — metadata の安全な削除](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
