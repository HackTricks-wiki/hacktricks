# Privacy-Preserving Communications and Sharing

End-to-end encryption はコンテンツを保護します。しかし、アカウント、電話番号、contact graph、IP address、push token、notification preview、タイミング、ファイルメタデータ、受信者の挙動を自動的に隠すわけではありません。ツールは、除去できるメタデータと新たに関与する監視者に基づいて選択してください。

## 通信モデルを比較する

| ツール/モデル | 有用な特性 | 残る監視者と制限 |
|---|---|---|
| Signal | 成熟した E2EE；usernames により番号を共有せずに連絡を開始可能；sealed sender により service metadata を削減 | 登録には電話番号が必要；service、push provider、contacts、endpoints に一部の観測情報が残る |
| SimpleX | グローバルな user identifier なし；contact ごとの queues；Tor transport は optional | Relay のタイミング/transport、push service、invitations、endpoints；新しく小規模な ecosystem |
| Briar | 直接 synchronization；オンライン時は Tor；オフライン時は Bluetooth/Wi-Fi；中央 message store なし | Contacts と endpoints；local radio observers；Android 中心；両者が利用可能であるか Mailbox を使う必要がある |
| OnionShare | 一時的な onion service を介した直接的な file/receive/chat/site；storage provider なし | Sender の computer が service になる；link bearer は access を知る；タイミングと endpoints は残る |
| `age` encrypted file | transport から独立した単純な recipient-key encryption | Transport には sender/recipient、タイミング、サイズが見える；filenames/archive metadata と endpoints は残る |
| 通常の email + TLS | Server-to-server channel encryption | 通常、両方の mail provider がコンテンツを読め、routing/account metadata を保持できる |

## Signal: 番号を開示しない private contact

Signal usernames を使うと、新しい contact にユーザーの電話番号を明かさずに chat を開始できますが、登録には電話番号が必要です。<sup>[[1]](#references)</sup> Sealed sender は段階的なメタデータ保護であり、すべての IP/タイミング相関への耐性ではありません。<sup>[[2]](#references)</sup>

### ワークフロー

1. 公式 app store/project から Signal をインストールし、先に OS を update します。
2. 合法的に使用する権利のある番号で登録します。レンタル SMS activation、他人の番号、または虚偽の身元で取得した provider account は使用しないでください。
3. **Settings → Privacy → Phone Number** で、threat model に応じて番号を閲覧できる人と、番号で account を検索できる人を設定します。
4. 新しい contact の discovery 用に username を作成します。既に authenticated な channel を通じて正確な link/QR を共有します。username は変更可能で、profile name とは異なります。
5. 利便性が linkage に見合わない場合は contact upload/permissions を無効にし、platform が対応していれば contacts を手動で追加します。
6. contact details を開き、機密性の高いコンテンツを送る前に、2つ目の channel または対面で safety number/QR を比較します。
7. linked devices、registration lock/PIN、notification previews、screen security、call relaying、disappearing-message defaults、backup behavior を確認します。
8. 機密性のない test message を送り、通話します。双方で lock-screen、desktop、wearable、cloud-notification の痕跡を確認します。
9. 変更された safety number や予期しない linked device は、自動的に閉じる alert ではなく、調査イベントとして扱います。

pseudonymous な profile photo、bio、group membership、schedule を、身元が特定される Signal context と混在させないでください。

## SimpleX: グローバル identifier なしの contact ごとの connections

SimpleX は unidirectional queues を通じて messages を routing し、network-wide user identifier を割り当てません。ただし、独自の policy では transport sessions、temporary server data、push-notification の tradeoffs、endpoint responsibility が文書化されています。<sup>[[3]](#references)</sup>

### ワークフロー

1. 継続的に保守されている client を公式 project/store から download し、publisher を verify します。identities を混在させてはならない場合は、専用の OS/app profile を使用します。
2. context 固有の display name と image を使った **local** profile を作成します。backup なしで app を削除すると、profile と connections を失う可能性があります。
3. 初回起動時に notification mode を意図的に選択します。Instant mobile push により、Apple/Google infrastructure に追加のメタデータが露出する可能性があります。
4. 1人の contact 用に one-time invitation link を作成します。authenticated channel を通じて転送します。live invitation を取得した人は誰でも、それを使用しようとする可能性があります。
5. 接続後、contact details を開き、対面または独立した verified channel を通じて security code を比較します。<sup>[[4]](#references)</sup>
6. 対応している場合は、無関係な groups 間で同じ profile を再利用せず、incognito の per-group profile を使用します。
7. local network/server から direct IP が見えないように、client が対応する Tor transport を設定します。変更後に connection を確認します。対応していない system proxy を無理に使用しないでください。
8. delivery receipts、link previews、calls、automatic downloads、database export/backup を確認します。それぞれがメタデータまたは endpoint exposure を変更します。
9. live profile state の重複を実行せず、分離した spare device で recovery をテストします。project は、同時に存在する copies が conversations を妨げる可能性があると警告しています。

グローバル identifier がなくても、content、profile reuse、invitation delivery、タイミング、social graph によって contact がユーザーを特定することは防げません。

## Briar: 直接的で disruption-resistant な messaging

Briar は devices 間で直接 synchronization を行い、オンライン時は Tor、local outage 時は Bluetooth/Wi-Fi を使用します。公式の threat model は短距離 radio に対する adversarial monitoring が限定的であることを前提としているため、local wireless は見えないわけではありません。<sup>[[5]](#references)</sup>

### ワークフロー

1. 公式 Briar distribution から install し、package source を verify します。最新の security updates が適用された supported Android device を使用します。
2. unique な context nickname と強力な password で local account を作成します。password-reset path はないため、unlock secret を復元できることをテストします。
3. 可能な場合は、互いの QR code を scan して対面で contacts を追加します。これにより contact が authenticated され、相関可能な channel を通じた link の送信を避けられます。
4. connectivity settings で必要な transport のみを有効にします：Tor/Internet、Wi-Fi、Bluetooth のいずれかまたは複数。不要な場合は local radios を無効にします。
5. 非同期 delivery には、専用の電源接続された device 上で Briar Mailbox を評価します。message server と同様に inventory を管理し、物理的に保護します。
6. Internet が利用可能な状態で benign な test を送信し、その後、所有者が許可した場所で Internet を無効にして、計画した outage path をテストします。
7. Android backups、notification previews、screenshots、exported content を確認します。local encrypted storage は endpoint の unlock/compromise 時に露出します。
8. 紛失した contacts/devices を削除し、physical custody または account password が compromise された場合は context 全体を廃止します。

## OnionShare: 直接的な一時 transfer

OnionShare は sender/receiver の computer 上で onion service を実行します。files は storage provider に upload されず、traffic は Tor 内で end-to-end encrypted されます。<sup>[[6]](#references)</sup> 完全な onion URL は bearer capability であり、保護する必要があります。

### GUI file-sharing ワークフロー

1. 公式の signed distribution から OnionShare を install し、recipient 側に Tor Browser を install します。
2. **sanitized copies** of files を専用の staging directory に置きます。OnionShare の対象として personal home directory を指定しないでください。
3. **Share Files** を開き、staged files のみを追加します。private key/access protection は有効のままにし、1人の recipient に対して **Stop sharing after files have been sent** を有効にします。
4. sharing を開始し、完全な onion URL を既に authenticated な E2EE channel を通じて送信します。email、issue trackers、public chats に貼り付けないでください。
5. recipient は Tor Browser で URL を開き、sender と expected filenames/size を確認して download します。
6. file 自体が security boundary である場合、integrity のために、事前合意または別途 delivery された SHA-256 digest を双方で比較します。
7. download 後に OnionShare が停止したことを確認します。停止していなければ手動で停止し、application を閉じます。
8. retention policy に従って staged copy を削除し、意図しない filename disclosure がないか OnionShare の history/log settings を確認します。

### CLI ワークフロー

公式 CLI は files を positional arguments として受け付け、デフォルトでは単一の completed share の後に停止します。公式 CLI/Tor が install された host 上では：
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
生成された完全なURLは安全に伝達してください。脅威モデルで生成される露出が明示的に必要とされていない限り、`--public`、`--no-autostop-sharing`、詳細なファイル名ログ、永続化を追加しないでください。<sup>[[7]](#references)</sup>

受信したドキュメントは敵対的なものとして扱ってください。identity-bearing host上ではなく、使い捨てVMまたはDangerzone形式のrendererで開いてください。

## `age`でファイルを個別に暗号化する

Transportに依存しない暗号化は、storage/email providerからオブジェクトを見られる可能性がある場合に有用です。ただし、sender、recipient、size、timing、filenameを別途処理しない限り、それらを隠すことはできません。

### Recipientのセットアップ
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
公開受信者文字列を第2のチャネルを通じて認証します。続いて送信者は次を実行します：
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
受信者は新しいパスに復号します：
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
公式 CLI は `-o` が既存の出力を上書きすることを警告するため、新しいディレクトリを使用し、移動する前に digest/content を検証してください。<sup>[[8]](#references)</sup> ciphertext と一緒に identity file を送信しないでください。

## 再現可能なファイル sanitization パイプライン

Metadata の削除方法は format 固有です。authenticity、forensics、または chain of custody が重要な場合は、暗号化された original を保持し、copy に対して操作してください。

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
これは ExifTool のより安全な JPEG ガイダンスに従ったものです。すべてのタグを無差別に削除すると、色の情報まで削除される可能性があります。<sup>[[9]](#references)</sup> その後、ピクセルを目視で確認し、顔、反射、画面、ランドマーク、固有の損傷やノイズのパターンがないか調べます。

### Office/PDF ワークフロー

1. 編集可能なオリジナルは暗号化し、公開環境から切り離してオフラインで保管します。
2. 作成アプリケーションで、コメント、変更履歴、非表示のスライドやシート、埋め込みファイル、個人用テンプレート、ドキュメントプロパティを削除します。
3. 専用のクリーンプロファイルから新しい PDF をエクスポートします。cloud printer に「印刷」しないでください。
4. フォーマット対応ツールと、使い捨てのビジュアルレンダラーの両方で確認します。
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. レンダリングされた出力から、名前、パス、メールアドレス、改訂テキストを検索します。Rasterization はアクティブな構造を除去できますが、アクセシビリティと検索性を損ない、表示されるコンテンツや文体を除去することはありません。
6. 最終成果物を Hash 化し、そのコピー**のみ**を publication compartment 経由で転送します。

## Privacy Pass: service designer 向け匿名認証

Privacy Pass は token の**発行**と**redeem**を分離します。origin は、client が issuer に承認された token を保有していることを知ることはできますが、client 固有の発行操作を知ることはできません。token の再利用、一意の metadata、タイミング、または共謀によって、linkability が再び生じる可能性があります。<sup>[[10]](#references)</sup>

安全な deployment pattern:

1. token が証明する statement（例: rate-limit の適格性）を定義し、隠れた global identity は定義しない。
2. 標準化された architecture と issuance protocol を使用し、blind-signature cryptography を from scratch で実装しない。
3. 必要な privacy property に応じて、issuer/attester と origin の administration を分離する。
4. public/private token metadata を最小化し、anonymity set が十分に大きいことを確認する。
5. 対応している場合は使用前に batch 発行し、発行時刻と redeem 時刻が単純に一致しないようにする。
6. 各 token は一度だけ redeem し、origin-bound challenge を検証し、期限切れの token state を削除する。
7. cookies、IP logging、application accounts によって token の privacy property がひそかに無効化されないようにする。
8. timing、metadata、または一意のエラーを使って、issuer と origin の logs が、管理下で行った発行イベントと redeem イベントを join できるかテストする。

Privacy Pass は application feature であり、ユーザーが任意の account に後付けできるものではありません。

## Communications verification checklist

- [ ] Contact/invitation/key が独立して authenticated されている。
- [ ] Phone number、username、profile、group、contact-upload の exposure を把握している。
- [ ] Direct IP、relay、Tor、push-provider、local-radio の observers を列挙している。
- [ ] Notification previews、wearables、linked desktops、backups をテストしている。
- [ ] Files を sanitized し、必要に応じて encrypted 化し、disposable context で開いている。
- [ ] 無関係な identities を bridge せずに recovery が機能する。
- [ ] Logs、history、temporary share services に shutdown/retention rule がある。

## References

- [1] [Signal — Phone Number Privacy and Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy and Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy and security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — How it works](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage and CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — official CLI and usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Safely removing metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
