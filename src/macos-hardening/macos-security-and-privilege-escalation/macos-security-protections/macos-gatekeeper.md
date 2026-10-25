# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**は、Mac operating system向けに開発されたセキュリティ機能で、ユーザーがシステム上で**信頼できるソフトウェアのみを実行する**ように設計されています。App Store以外の**ソース**からダウンロードしたアプリ、プラグイン、インストーラパッケージなどをユーザーが開こうとした際に、そのソフトウェアを**検証**します。

Gatekeeperの主要な仕組みは、**検証**プロセスです。ダウンロードしたソフトウェアが**認定された開発者によって署名されている**かを確認し、ソフトウェアの真正性を確かめます。さらに、ソフトウェアがAppleによって**notarisedされている**かを確認し、既知の悪意あるコンテンツが含まれておらず、notarisation後に改ざんされていないことを確かめます。

また、Gatekeeperは、ダウンロードしたソフトウェアを初めて開く際に**ユーザーに承認を求める**ことで、ユーザーの制御とセキュリティを強化します。この保護機能により、無害なデータファイルだと思い込んだファイルから、潜在的に有害な実行可能コードを誤って実行してしまうことを防げます。

### Application Signatures

Application signatures（code signaturesとも呼ばれます）は、Appleのセキュリティ基盤における重要な要素です。これらは**ソフトウェアの作成者（開発者）の身元を検証**し、最後に署名されてからコードが改ざんされていないことを確認するために使われます。

仕組みは次のとおりです。

1. **アプリケーションへの署名:** 開発者がアプリケーションを配布する準備ができると、**秘密鍵を使ってアプリケーションに署名**します。この秘密鍵は、Apple Developer Programへの登録時に**Appleが開発者に発行する証明書**に紐づいています。署名プロセスでは、アプリのすべての部分の暗号学的ハッシュを作成し、このハッシュを開発者の秘密鍵で暗号化します。
2. **アプリケーションの配布:** 署名されたアプリケーションは、対応する公開鍵を含む開発者の証明書とともにユーザーに配布されます。
3. **アプリケーションの検証:** ユーザーがアプリケーションをダウンロードして実行しようとすると、Mac operating systemは開発者の証明書に含まれる公開鍵を使ってハッシュを復号します。次に、アプリケーションの現在の状態をもとにハッシュを再計算し、復号したハッシュと比較します。一致すれば、**開発者が署名してからアプリケーションが変更されていない**ことを意味し、システムはアプリケーションの実行を許可します。

Application signaturesは、AppleのGatekeeper technologyに不可欠な要素です。ユーザーが**インターネットからダウンロードしたアプリケーションを開こうとする**と、Gatekeeperはアプリケーションの署名を検証します。既知の開発者にAppleが発行した証明書で署名されており、コードが改ざんされていなければ、Gatekeeperはアプリケーションの実行を許可します。それ以外の場合は、アプリケーションをブロックしてユーザーに警告します。

macOS Catalina以降、**GatekeeperはアプリケーションがAppleによってnotarizedされているかも確認**し、セキュリティをさらに強化しています。notarizationプロセスでは、既知のセキュリティ上の問題や悪意のあるコードがないかアプリケーションを確認します。これらのチェックに合格すると、AppleはGatekeeperが検証できるticketをアプリケーションに追加します。

#### 署名の確認

**malware sample**を調べる際は、そのバイナリの**署名を必ず確認してください**。署名した**開発者**が、すでに**malware**と**関連している**可能性があります。

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```

### Notarization

Appleのnotarizationプロセスは、潜在的に有害なソフトウェアからユーザーを保護するための追加の安全策です。このプロセスでは、**開発者がアプリケーションをAppleのNotary Serviceによる審査に提出**します。これはApp Reviewとは異なります。このサービスは、提出されたソフトウェアに**悪意のあるコンテンツ**が含まれていないか、またコード署名に問題がないかを精査する**自動システム**です。

ソフトウェアが問題なくこの審査に**合格**すると、Notary Serviceはnotarization ticketを生成します。その後、開発者はこのticketを**ソフトウェアに添付する**必要があります。この処理は「stapling」と呼ばれます。さらに、notarization ticketはオンラインにも公開され、Gatekeeper（Appleのセキュリティ技術）がアクセスできるようになります。

ユーザーが初めてソフトウェアをインストールまたは実行すると、実行ファイルにstapleされたticket、またはオンラインで見つかったticketの存在によって、**そのソフトウェアがAppleによってnotarizationされたことがGatekeeperに通知されます**。その結果、Gatekeeperは初回起動時のダイアログに説明メッセージを表示し、そのソフトウェアがAppleによる悪意のあるコンテンツの検査を受けたことを知らせます。これにより、ユーザーがシステムにインストールまたは実行するソフトウェアの安全性に対する信頼が高まります。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia以降では、**`spctl`**を使ってGatekeeperの設定を変更できなくなったことに注意してください。

**`spctl`**は、Gatekeeperを列挙して操作するためのCLIツールです（XPCメッセージを介して`syspolicyd`デーモンと通信します）。たとえば、次のようにしてGateKeeperの**ステータス**を確認できます。

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> GateKeeperの署名チェックは、すべてのファイルではなく、**Quarantine属性を持つファイルに対してのみ**実行されます。

GateKeeperは、**設定と署名**に基づいてバイナリを実行できるかどうかをチェックします。

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**は、Gatekeeperの適用を担う主要なデーモンです。`/var/db/SystemPolicy`にデータベースを保持しています。[データベースをサポートするコード](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)と[SQLテンプレート](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)を確認できます。このデータベースはSIPによる制限を受けず、rootが書き込み可能です。また、データベース`/var/db/.SystemPolicy-default`は、もう一方のデータベースが破損した場合に備えた元のバックアップとして使用されます。

さらに、バンドル**`/var/db/gke.bundle`**と**`/var/db/gkopaque.bundle`**には、データベースに挿入されるルールを含むファイルがあります。rootとして次のコマンドを実行すると、このデータベースを確認できます:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` などの異なる操作を提供する XPC サーバーも公開しています。これらの操作は **`Security.framework` の `SecAssessment*`** API からも利用でき、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初のルールが「**App Store**」で終わり、2つ目のルールが「**Developer ID**」で終わっていること、そして前の画像では **App Store のアプリと識別済みの開発者のアプリを実行できる設定になっていた**ことに注目してください。\
この設定を App Store に**変更**すると、「**Notarized Developer ID**」のルールは表示されなくなります。

**GKE** タイプのルールも数千件あります：

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

これらは次のファイルに含まれるハッシュです。

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

または、次のコマンドで前述の情報を一覧表示できます。

```bash
sudo spctl --list
```

**`spctl`** の **`--master-disable`** および **`--global-disable`** オプションを使用すると、これらの署名チェックが完全に **無効化** されます。

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

完全に有効にすると、新しいオプションが表示されます。

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

次の方法で、**AppがGateKeeperによって許可されるかどうかを確認**できます。

```bash
spctl --assess -v /Applications/App.app
```

macOS 14以降では、**`syspolicy_check`** はアプリケーションバンドルの配布前チェックに役立つ、より高水準のツールです。単なる `spctl` の結果よりも実用的な trusted-execution 診断を出力しますが、Appleは、quarantine の伝播も確認できるため、実際のダウンロード、展開、初回起動の経路をテストすることを引き続き推奨しています。<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

GateKeeper に新しいルールを追加して、特定のアプリの実行を許可できます：

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```

**kernel extensions**については、`/var/db/SystemPolicyConfiguration`フォルダに、読み込みを許可されたkextのリストを含むファイルがあります。さらに、`spctl`には`com.apple.private.iokit.nvram-csr` entitlementがあります。これは、新たに事前承認されたkernel extensionsを追加でき、それらをNVRAMの`kext-allowed-teams`キーにも保存する必要があるためです。

#### macOS 15 (Sequoia)以降でのGatekeeperの管理

- Finderの従来からある**Ctrl+Open / 右クリック → Open**によるbypassは削除されました。ブロックダイアログが最初に表示された後、ユーザーは**System Settings → Privacy & Security → Open Anyway**から、ブロックされたアプリを明示的に許可する必要があります。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable`は、ユーザーの操作なしにポリシーを変更する方法として受け付けられなくなりました。ルールデータベースまたはグローバルな評価状態を変更する操作はdeprecatedになったため、評価には`spctl`を使用し、強制適用の設定はUIまたはMDMから行ってください。

macOS 15 Sequoia以降、エンドユーザーは`spctl`からGatekeeperポリシーを切り替えられなくなりました。管理はSystem Settingsを使うか、`com.apple.systempolicy.control` payloadを含むMDM configuration profileを配布して行います。App Storeとidentified developersを許可し（「Anywhere」は許可しない）するプロファイルの例：

<details>
<summary>App Storeとidentified developersを許可するMDM profile</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.systempolicy.control</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.example.gatekeeper</string>
      <key>EnableAssessment</key>
      <true/>
      <key>AllowIdentifiedDevelopers</key>
      <true/>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.example.profile.gatekeeper</string>
  <key>PayloadUUID</key>
  <string>00000000-0000-0000-0000-000000000000</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadDisplayName</key>
  <string>Gatekeeper</string>
</dict>
</plist>
```

</details>

### Quarantine Files

アプリケーションまたはファイルを**ダウンロード**すると、Webブラウザやメールクライアントなどの特定のmacOS **アプリケーション**は、ダウンロードしたファイルに「**quarantine flag**」と一般に呼ばれる拡張ファイル属性を**付与します**。この属性は、ファイルが信頼できないソース（インターネット）から取得されたものであり、リスクを伴う可能性があることを**示す**セキュリティ対策として機能します。ただし、すべてのアプリケーションがこの属性を付与するわけではありません。たとえば、一般的なBitTorrentクライアントソフトウェアは通常、この処理を省略します。

**quarantine flagがあると、ユーザーがファイルを実行しようとした際に、macOSのGatekeeperセキュリティ機能が作動します**。

**quarantine flagが存在しない場合**（一部のBitTorrentクライアント経由でダウンロードしたファイルなど）、Gatekeeperの**チェックが実行されない可能性があります**。そのため、ユーザーは安全性の低い、または不明なソースからダウンロードしたファイルを開く際に注意が必要です。

> [!NOTE] > コード署名の**有効性**を**確認**する処理は、コードおよび同梱リソースすべての暗号学的**ハッシュ**を生成するため、**リソースを大量に消費します**。さらに、証明書の有効性を確認するには、発行後に失効していないかを確認するため、Appleのサーバーに**オンラインで問い合わせる**必要があります。こうした理由から、アプリを起動するたびにコード署名とnotarizationを完全にチェックするのは**現実的ではありません**。
>
> そのため、これらのチェックは、quarantine属性が付与されたアプリを実行する場合に**のみ実行されます**。

> [!WARNING]
> この属性は、ファイルを作成またはダウンロードする**アプリケーションが設定する必要があります**。
>
> ただし、sandbox化されたアプリケーションは、作成するすべてのファイルにこの属性を設定します。sandbox化されていないアプリは、自身で設定することも、[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)キーを**Info.plist**で指定することもできます。これにより、システムは作成されたファイルに`com.apple.quarantine`拡張属性を設定します。

また、**`qtn_proc_apply_to_self`**を呼び出したプロセスが作成したすべてのファイルはquarantineされます。または、API **`qtn_file_apply_to_path`**を使うと、指定したファイルパスにquarantine属性が追加されます。

以下の方法で、状態の**確認と有効化／無効化**（root権限が必要）が可能です:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

次の方法で、ファイルに **quarantine 拡張属性** があるかどうかも確認できます:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

**拡張** **属性**の**値**を確認し、次の方法で quarantine 属性を書き込んだアプリを特定します:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

実際、プロセスは「作成したファイルに quarantine フラグを設定できる」（作成したファイルに USER_APPROVED フラグを適用しようとしましたが、設定できませんでした）：

<details>

<summary>quarantine フラグを適用するソースコード</summary>

```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
    QTN_FLAG_DOWNLOAD = 0x0001,
    QTN_FLAG_SANDBOX = 0x0002,
    QTN_FLAG_HARD = 0x0004,
    QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

  qtn_proc_t qp = qtn_proc_alloc();
  qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
  qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
  qtn_proc_apply_to_self(qp);
  qtn_proc_free(qp);

  FILE *fp;
  fp = fopen("thisisquarantined.txt", "w+");
  fprintf(fp, "Hello Quarantine\n");
  fclose(fp);

  return 0;

}
```

</details>

そして、その属性を次のコマンドで**削除**します：

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

また、次のコマンドですべての隔離されたファイルを見つけます:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine情報は、LaunchServicesが管理する中央データベース **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** にも保存されます。これにより、GUIはファイルの取得元に関するデータを取得できます。さらに、取得元を隠すことに関心のあるアプリケーションによって、この情報が上書きされる可能性があります。また、これはLaunchServices APIからも実行できます。

#### **libquarantine.dylib**

このライブラリは、拡張属性のフィールドを操作するための複数の関数をエクスポートします。

`qtn_file_*` APIはファイルのQuarantineポリシーを扱い、`qtn_proc_*` APIはプロセスに適用されます（そのプロセスが作成したファイルが対象です）。エクスポートされていない `__qtn_syscall_quarantine*` 関数がポリシーを適用するもので、「Quarantine」を最初の引数として `mac_syscall` を呼び出し、リクエストを `Quarantine.kext` に送信します。

#### **Quarantine.kext**

このカーネル拡張は、システム上の **kernel cache** からのみ利用できます。ただし、[**https://developer.apple.com/**](https://developer.apple.com/) から **Kernel Debug Kit** をダウンロードできます。これには、シンボル情報付きの拡張機能が含まれています。

このKextはMACFを介して複数の呼び出しをフックし、ファイルのライフサイクルに関するすべてのイベントを捕捉します。対象となるのは、作成、オープン、名前変更、hard-linkingなどです。また、`setxattr` もフックして、`com.apple.quarantine` 拡張属性の設定を防ぎます。

また、いくつかのMIBも使用します。

- `security.mac.qtn.sandbox_enforce`: Sandboxと連携してQuarantineを強制する
- `security.mac.qtn.user_approved_exec`: Quarantine対象のプロセスは、承認されたファイルのみ実行できる

#### Provenance xattr (Ventura以降)

macOS 13 Venturaでは、Quarantine対象のアプリが初めて実行を許可されたときに設定される、独立したprovenanceメカニズムが導入されました。<sup>[[2]](#references)</sup> 次の2つの成果物が作成されます。

- `.app` バンドルディレクトリの `com.apple.provenance` xattr（主キーとフラグを含む固定サイズのバイナリ値）。
- ExecPolicyデータベース（`/var/db/SystemPolicyConfiguration/ExecPolicy/`）内の `provenance_tracking` テーブルの行。アプリのcdhashとメタデータが保存されます。

実際の使用例：

```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```

### XProtect

XProtectはmacOSに組み込まれた**マルウェア対策**機能です。XProtectは、アプリケーションが初めて起動されたとき、または変更されたときに、既知のマルウェアや安全でないファイル形式のデータベースと照合して**チェックします**。Safari、Mail、Messagesなどの特定のアプリを通じてファイルをダウンロードすると、XProtectは自動的にそのファイルをスキャンします。データベースに登録された既知のマルウェアと一致した場合、XProtectは**ファイルの実行を防止**し、脅威を警告します。

XProtectのデータベースは、Appleによって新しいマルウェア定義で**定期的に更新**され、これらの更新はMacに自動的にダウンロードされ、インストールされます。これにより、XProtectは常に最新の既知の脅威に対応した状態に保たれます。

ただし、**XProtectは多機能なアンチウイルスソリューションではありません**。特定の既知の脅威リストとの照合のみを行い、ほとんどのアンチウイルスソフトウェアのようなアクセス時スキャンは実行しません。

最新のXProtectアップデートに関する情報は、次のコマンドを実行すると取得できます:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtectはSIPで保護された場所 **/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあり、バンドル内にはXProtectが使用する情報があります。

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらのcdhashを持つコードがlegacy entitlementsを使用できるようにします。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleIDとTeamIDによって読み込みが禁止されているプラグインや拡張機能、または最低バージョンを指定する一覧です。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malwareを検出するYaraルールです。
- **`XProtect.bundle/Contents/Resources/gk.db`**: ブロックされたアプリケーションとTeamIDのハッシュを含むSQLite3データベースです。

XProtectに関連する別のAppが **`/Library/Apple/System/Library/CoreServices/XProtect.app`** にありますが、Gatekeeperプロセスには関与していません。

> XProtect Remediator: 最新のmacOSでは、Appleはオンデマンドスキャナー（XProtect Remediator）を提供しています。これらはlaunchd経由で定期的に実行され、さまざまなmalwareファミリーを検出して修復します。これらのスキャンはunified logsで確認できます。
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeperではない

> [!CAUTION]
> Gatekeeperはアプリケーションを実行するたびに**実行されるわけではありません**。_**AppleMobileFileIntegrity**_ (AMFI) は、Gatekeeperによってすでに実行・検証されたアプリを実行する際にのみ、**実行可能コードの署名を検証**します。

そのため、以前はアプリを実行してGatekeeperにキャッシュさせた後、**アプリケーション内の実行可能ファイルではないファイル**（ElectronのasarやNIBファイルなど）を変更し、ほかに保護機構がなければ、悪意のある追加要素を含むアプリケーションを**実行**できました。

しかし現在は、macOSがアプリケーションバンドル内のファイルの変更を**防ぐ**ため、これはできません。[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)攻撃を試すと、アプリを実行してGatekeeperにキャッシュさせた後、バンドルを変更できないため、もはや悪用できないことがわかります。また、exploitの説明どおりに`Contents`ディレクトリの名前を`NotCon`に変更し、アプリのメインバイナリを実行してGatekeeperにキャッシュさせようとしても、エラーが発生して実行されません。

## Gatekeeperのバイパス

Gatekeeperをバイパスする方法（Gatekeeperが阻止するはずのファイルをユーザーにダウンロードさせ、実行させる方法）は、macOSの脆弱性とみなされます。過去にGatekeeperのバイパスを可能にした手法に割り当てられたCVEを以下に示します。

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**を使って展開すると、**パスが886文字を超える**ファイルにはcom.apple.quarantine拡張属性が付与されないことが確認されました。このため、これらのファイルは意図せずGatekeeperのセキュリティチェックを**回避できます**。<sup>[[5]](#references)</sup>

詳細については、[**元のレポート**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を確認してください。<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**でアプリケーションを作成すると、実行する内容に関する情報は実行ファイルではなく、`application.app/Contents/document.wflow`に格納されます。実行ファイルは、**Automator Application Stub**と呼ばれる汎用のAutomatorバイナリにすぎません。

そのため、`application.app/Contents/MacOS/Automator\ Application\ Stub`を**システム内の別のAutomator Application Stubへのシンボリックリンクにすれば**、`document.wflow`内のスクリプトを**Gatekeeperを起動させずに**実行できます。実際の実行ファイルにquarantine xattrが付いていないためです。<sup>[[6]](#references)</sup>

想定される場所の例: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については、[**元のレポート**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を確認してください。<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

このバイパスでは、`application.app`ではなく`application.app/Contents`から圧縮を開始するようにして、アプリケーションを含むzipファイルを作成しました。そのため、**`application.app/Contents`内のすべてのファイルにはquarantine attrが付与されました**が、Gatekeeperがチェックする**`application.app`には付与されませんでした**。その結果、`application.app`が起動されたときに**quarantine属性が付いていなかった**ため、Gatekeeperをバイパスできました。<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

詳細については[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)を確認してください。<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントは異なりますが、この脆弱性の悪用方法は前述のものと非常によく似ています。この場合、**`application.app/Contents`** から Apple Archive を生成するため、**Archive Utility**で展開しても**`application.app`**には quarantine attr が設定されません。<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

詳細については、[**元のレポート**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)を確認してください。<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**を使用すると、ファイルへの属性の書き込みを誰にも許可しないようにできます。

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

さらに、**AppleDouble** file formatでは、ACEsを含めてファイルがコピーされます。<sup>[[9]](#references)</sup>

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)を見ると、**`com.apple.acl.text`**というxattrに保存されたACLのテキスト表現が、展開後のファイルにACLとして設定されることがわかります。つまり、ほかのxattrの書き込みを禁止するACLを付けて、アプリケーションを**AppleDouble** file formatのzipファイルに圧縮すると、アプリケーションにquarantine xattrが設定されません。

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

詳細については、[**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。<sup>[[9]](#references)</sup> サイドカーの作成と検証の手順については、[AppleDouble/ACL reproduction](macos-fs-tricks/macos-xattr-acls-extra-stuff.md)を参照してください。

これは AppleArchives を使っても悪用できる可能性があることに注意してください。

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

macOS内部の問題により、**Google Chromeがダウンロードしたファイルにquarantine属性を設定していなかった**ことが判明しました。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDoubleは、ファイルの属性を名前が`._`で始まる別ファイルに保存します。これにより、**macOSマシン間で**ファイル属性をコピーできます。しかし、AppleDoubleファイルを展開した後、`._`で始まるファイルには**quarantine属性が付与されていませんでした**。<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

quarantine attributeが設定されないファイルを作成できるため、**Gatekeeperを回避することが可能でした。**その手法は、AppleDoubleの命名規則（`._`で始まる）を使用して**DMGファイルのアプリケーションを作成**し、quarantine attributeのないこの隠しファイルへのシンボリックリンクとして**表示ファイルを作成する**というものです。\
**DMGファイルを実行すると**、quarantine attributeが設定されていないため、**Gatekeeperを回避します。**

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

### [CVE-2023-41067]

Appleはチェックを強化し、macOS Sonoma 14.0でLaunchServicesのロジックエラーを修正しました。公開された勧告には、アプリがGatekeeperを回避できる可能性があるとしか記載されていないため、CVEの記載だけから特定のキャリア形式や攻撃チェーンを推測しないでください。<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4（2024年3月リリース）におけるGatekeeperの回避は、悪意のあるZIPを`libarchive`が処理する方法に起因し、アプリがアセスメントを回避できました。Appleがこの問題を修正した14.4以降にアップデートしてください。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードしたアプリに埋め込まれた**Automator Quick Action workflow**が、Gatekeeperのアセスメントなしで実行される可能性がありました。workflowはデータとして扱われ、通常のnotarizationプロンプト経路の外でAutomatorヘルパーによって実行されていたためです。したがって、シェルスクリプトを実行するQuick Actionをバンドルした細工済み`.app`（例：`Contents/PlugIns/*.workflow/Contents/document.wflow`内）は、起動時に即座に実行される可能性がありました。Appleは追加の同意ダイアログを導入し、Ventura **13.7**、Sonoma **14.7**、Sequoia **15**でアセスメント経路を修正しました。<sup>[[3]](#references)</sup>

### 展開およびコピー時におけるQuarantine伝播の不具合

2024年の調査では、テスト対象バージョンのiZip（ZIP/TAR/7Z）、Archiver（ARCHIVER/ZIP/TAR/7Z）、BetterZip（ZIP/TAR/7Z）、WinRAR（ZIP/TAR/7Z）、7z Utility（DMG/ZIP/7Z）で伝播の欠落が確認されました。また、VMware Toolsによるホストからゲストへのコピー中に属性が失われることも観察されました。その後、複数のベンダーが修正を発表しているため、これらの名称は恒久的な脆弱ソフトウェア一覧ではなく、**バージョンごとの再テスト**の手がかりとして扱ってください。同じ信頼境界の問題は、ネイティブなUnixワークフローにも当てはまります。`curl`/`scp`はquarantineを追加せず、コマンドラインの`tar`/`unzip`はキャリアアーカイブから自動的にquarantineを継承しません。<sup>[[15]](#references)</sup>

攻撃側のテストでは、ブラウザー、メールクライアント、アーカイブ、ディスクイメージ、クラウド同期、共有フォルダー、VMコピーの**すべての**移行後に、キャリアと最終的なアプリを比較してください。`spctl`による明示的な拒否でも、欠落したxattrは修復されません。quarantineがなければ、通常の初回起動時のGatekeeper経路でアセスメントが要求されない可能性があります。<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- appを含むディレクトリを作成する。
- appにuchgを追加する。
- appをtar.gzファイルに圧縮する。
- tar.gzファイルを被害者に送る。
- 被害者がtar.gzファイルを開き、appを実行する。
- Gatekeeperはappをチェックしない。<sup>[[12]](#references)</sup>

### Quarantine xattrを防ぐ

「.app」バンドルにquarantine xattrが追加されていない場合、実行時に**Gatekeeperは起動しません**。

拡張属性を防止または破棄できる、ファイルシステム、フラグ、ACL、AppleDoubleベースのプリミティブについては、[macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks)を参照してください。





## References

- [1] [Apple Platform Security: macOS Sonoma 14.4のセキュリティコンテンツについて（CVE-2024-27853を含む）](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOSがアプリの出所を追跡する方法](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7のセキュリティコンテンツについて（CVE-2024-44128）](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 SequoiaでControlキーを押しながらクリックして「開く」を選ぶGatekeeperバイパスが廃止](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810の発見](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990、macOS Gatekeeperのバイパス](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs、Gatekeeperバイパスを可能にするSafariの脆弱性を特定](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs、Gatekeeperバイパスを可能にするmacOS Archive Utilityの脆弱性を特定（CVE-2022-32910）](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeperのアキレス腱：macOSの脆弱性を発掘](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeperバイパスの発見（CVE-2023-27943）](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitorの協力によるGatekeeperバイパスのエクスプロイトの発見と報告](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOSのセキュリティとプライバシーの仕組みをバイパスする — GatekeeperからSystem Integrity Protectionまで（Koh Nakagawa）](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14のセキュリティコンテンツについて（CVE-2023-41067）](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: 公証済み製品のテスト](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeperバイパス — macOSのセキュリティ機構の弱点を明らかにする](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
