# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** は Mac オペレーティングシステム向けに開発されたセキュリティ機能で、ユーザーがシステム上で**信頼できるソフトウェアのみを実行する**ように設計されています。これは、ユーザーが**App Store 外のソース**からダウンロードして開こうとするソフトウェア（アプリ、プラグイン、インストーラパッケージなど）を**検証**することで機能します。

Gatekeeper の主要な仕組みは、その**検証**プロセスにあります。ダウンロードしたソフトウェアが**認識された開発者によって署名されているか**を確認し、ソフトウェアの真正性を保証します。さらに、そのソフトウェアが Apple によって**notarised されているか**を確認し、既知の悪意あるコンテンツが含まれておらず、notarisation 後に改ざんされていないことを確認します。

また、Gatekeeper は、ダウンロードしたソフトウェアを初めて開く際に**ユーザーへ承認を求める**ことで、ユーザーによる制御とセキュリティを強化します。この保護機能は、無害なデータファイルだと思い込んでいた、潜在的に有害な実行可能コードをユーザーが誤って実行することを防ぐのに役立ちます。

### Application Signatures

Application signatures（code signatures とも呼ばれます）は、Apple のセキュリティインフラストラクチャにおける重要な構成要素です。これは、**ソフトウェア作成者（開発者）の身元を検証**し、最後に署名されて以降コードが改ざんされていないことを保証するために使用されます。

仕組みは次のとおりです。

1. **アプリケーションへの署名：** 開発者がアプリケーションを配布する準備が整うと、**private key を使用してアプリケーションに署名**します。この private key は、開発者が Apple Developer Program に登録した際に **Apple が開発者へ発行する certificate** に関連付けられています。署名プロセスでは、アプリのすべての部分から cryptographic hash を作成し、その hash を開発者の private key で暗号化します。
2. **アプリケーションの配布：** 署名済みアプリケーションは、対応する public key を含む開発者の certificate とともにユーザーへ配布されます。
3. **アプリケーションの検証：** ユーザーがアプリケーションをダウンロードして実行しようとすると、Mac オペレーティングシステムは開発者の certificate に含まれる public key を使用して hash を復号します。次に、アプリケーションの現在の状態に基づいて hash を再計算し、復号した hash と比較します。一致した場合、**開発者が署名して以降、アプリケーションが変更されていない**ことを意味し、システムはアプリケーションの実行を許可します。

Application signatures は Apple の Gatekeeper テクノロジーに不可欠な要素です。ユーザーが**インターネットからダウンロードしたアプリケーションを開こうとすると**、Gatekeeper は application signature を検証します。Apple が既知の開発者へ発行した certificate で署名されており、コードが改ざんされていなければ、Gatekeeper はアプリケーションの実行を許可します。それ以外の場合、アプリケーションをブロックしてユーザーに警告します。

macOS Catalina 以降、**Gatekeeper はアプリケーションが Apple によって notarized されているかどうかも確認**するようになり、セキュリティがさらに強化されました。notarization プロセスでは、既知のセキュリティ問題や悪意あるコードがないかアプリケーションを確認します。これらのチェックに合格すると、Apple は Gatekeeper が検証できる ticket をアプリケーションに追加します。

#### Check Signatures

**malware sample** を確認する際は、バイナリの**signature を必ず確認**してください。署名した**developer**がすでに**malware**と**関連している**可能性があるためです。
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

Appleのnotarizationプロセスは、潜在的に有害なsoftwareからユーザーを保護するための追加の安全対策です。これには、**developerが自身のapplicationを、App Reviewと混同してはならない**Apple's Notary Serviceによる審査に提出することが含まれます。このserviceは、提出されたsoftwareに**malicious content**が含まれていないか、またcode-signingに潜在的な問題がないかを精査する**automated system**です。

softwareが問題を検出されることなくこの検査に**合格**すると、Notary Serviceはnotarization ticketを生成します。その後、developerはこのticketを**自身のsoftwareに添付**する必要があります。このプロセスは'stapling'と呼ばれます。さらに、notarization ticketはonlineにも公開され、Appleのsecurity technologyであるGatekeeperがアクセスできるようになります。

ユーザーがsoftwareを初めてinstallまたはexecuteすると、notarization ticketがexecutableにstapledされているかonlineで見つかるかにかかわらず、**softwareがAppleによってnotarizedされていることをGatekeeperに通知します**。その結果、Gatekeeperは初回launch dialogに説明メッセージを表示し、そのsoftwareがAppleによるmalicious contentのチェックを受けたことを示します。このプロセスにより、ユーザーがsystemにinstallまたはrunするsoftwareのsecurityに対する信頼が高まります。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version以降、**`spctl`**ではGatekeeper configurationを変更できなくなったことに注意してください。

**`spctl`**は、Gatekeeper（XPC messagesを介して`syspolicyd` daemonと通信）を列挙および操作するためのCLI toolです。例えば、次のコマンドで**GateKeeper**の**status**を確認できます。
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper の署名チェックは、すべてのファイルではなく、**Quarantine 属性を持つファイル**に対してのみ実行されることに注意してください。

GateKeeper は、**preferences と署名**に従ってバイナリを実行できるかどうかをチェックします：

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** は、Gatekeeper の強制を担う主要な daemon です。`/var/db/SystemPolicy` にあるデータベースを管理しており、[データベースをサポートするコードはこちら](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)、[SQL templateはこちら](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)で確認できます。このデータベースは SIP の制限を受けず、root による書き込みが可能です。また、データベース `/var/db/.SystemPolicy-default` は、他方のデータベースが破損した場合に備えた元のバックアップとして使用されます。

さらに、bundle **`/var/db/gke.bundle`** と **`/var/db/gkopaque.bundle`** には、データベースに挿入されるルールを含むファイルがあります。root として、次のコマンドでこのデータベースを確認できます：
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
**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` などの異なる操作を持つ XPC server も公開しており、これらは **`Security.framework`'s `SecAssessment*`** APIs を使って到達することもできます。また、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初の rule が "**App Store**" で終わり、2 番目の rule が "**Developer ID**" で終わっていること、そして前のイメージでは **App Store と識別済みの開発者からの apps の実行が有効になっていた**ことに注目してください。\
その設定を App Store に**変更**すると、"**Notarized Developer ID" rules は消えます**。

**type GKE** の rules も数千存在します：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
これらは以下から取得された hash です。

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

または、以下で前述の情報を一覧表示できます：
```bash
sudo spctl --list
```
**`spctl`** のオプション **`--master-disable`** と **`--global-disable`** は、これらの署名チェックを完全に **無効化** します：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全に有効化すると、新しいオプションが表示されます：

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

以下を使用して、**App が GateKeeper によって許可されるかどうかを確認**できます：
```bash
spctl --assess -v /Applications/App.app
```
GateKeeperに新しいルールを追加して、特定のアプリの実行を許可できます：
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
**kernel extensions** に関しては、フォルダー `/var/db/SystemPolicyConfiguration` に、ロードを許可された kexts のリストを含むファイルがあります。さらに、`spctl` には `com.apple.private.iokit.nvram-csr` entitlement があります。これは、事前承認済みの新しい kernel extensions を追加でき、それらを `kext-allowed-teams` key として NVRAM にも保存する必要があるためです。

#### macOS 15 (Sequoia) 以降での Gatekeeper の管理

- 長年利用されてきた Finder の **Ctrl+Open / 右クリック → 開く** bypass は削除されました。ユーザーは、最初の block dialog の後、**システム設定 → プライバシーとセキュリティ → Open Anyway** から block された app を明示的に許可する必要があります。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` は受け付けられなくなりました。`spctl` は実質的に assessment と label management のための read-only ツールとなり、policy enforcement は UI または MDM を通じて設定されます。

macOS 15 Sequoia 以降、end users は `spctl` から Gatekeeper policy を切り替えられなくなりました。管理はシステム設定から行うか、`com.apple.systempolicy.control` payload を含む MDM configuration profile を deploy して行います。以下は、App Store と identified developers を許可する（ただし「Anywhere」は許可しない）profile の例です。

<details>
<summary>App Store と identified developers を許可する MDM profile</summary>
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

アプリケーションまたはファイルを**ダウンロード**すると、Webブラウザやメールクライアントなどの特定のmacOS **applications**は、一般に「**quarantine flag**」と呼ばれる**拡張ファイル属性**をダウンロードしたファイルに付加します。この属性は、**ファイルに印を付ける**セキュリティ対策として機能し、そのファイルが信頼できないソース（インターネット）から取得されたものであり、潜在的なリスクを含む可能性があることを示します。ただし、すべてのアプリケーションがこの属性を付加するわけではありません。たとえば、一般的なBitTorrentクライアントソフトウェアは通常、この処理を回避します。

**quarantine flagの存在は、ユーザーがファイルを実行しようとした際に、macOSのGatekeeperセキュリティ機能を作動させます**。

**quarantine flagが存在しない場合**（一部のBitTorrentクライアント経由でダウンロードしたファイルなど）、Gatekeeperの**チェックが実行されない可能性があります**。そのため、ユーザーは安全性の低い、または未知のソースからダウンロードしたファイルを開く際に注意する必要があります。

> [!NOTE] > コード署名の**有効性**を**確認する**処理は、コードとそのすべてのバンドルリソースの暗号学的**ハッシュ**を生成する必要があり、**リソースを大量に消費**します。さらに、証明書の有効性を確認するには、発行後に失効していないかをAppleのサーバーに対して**オンラインチェック**する必要があります。これらの理由から、アプリを起動するたびに完全なコード署名およびnotarizationチェックを実行するのは**現実的ではありません**。
>
> したがって、これらのチェックは**quarantined属性を持つアプリを実行するときにのみ実行されます**。

> [!WARNING]
> この属性は、ファイルを作成またはダウンロードするアプリケーションによって**設定される必要があります**。
>
> ただし、sandbox化されたファイルには、作成するすべてのファイルにこの属性が設定されます。また、non sandboxedアプリは自分で設定することも、[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)キーを**Info.plist**で指定することもできます。これにより、システムは作成されたファイルに`com.apple.quarantine`拡張属性を設定します。

さらに、**`qtn_proc_apply_to_self`**を呼び出すプロセスによって作成されたすべてのファイルはquarantinedになります。また、API **`qtn_file_apply_to_path`**は、指定されたファイルパスにquarantine属性を追加します。

**ステータスの確認および有効化/無効化**（rootが必要）は、次の方法で実行できます。
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
また、次のコマンドで**ファイルに quarantine 拡張属性があるか確認できます**：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**拡張** **属性**の**値**を確認し、次のコマンドで quarantine 属性を書き込んだ app を特定します：
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
実際、プロセスは「作成するファイルに quarantine flags を設定できる」可能性があります（作成したファイルに USER_APPROVED flag を適用しようとしましたが、適用できませんでした）。

<details>

<summary>quarantine flags を適用する Source Code</summary>
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

また、次のコマンドで**その属性を削除**します。
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
また、次のコマンドですべての隔離されたファイルを見つけます:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine情報は、**`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** にあるLaunchServices管理の中央データベースにも保存されており、GUIがファイルの出所に関するデータを取得できるようになっています。さらに、これは出所を隠したいアプリケーションによって上書きされる可能性があります。また、これはLaunchServices APIから実行できます。

#### **libquarantine.dylib**

このライブラリは、拡張属性フィールドを操作できる複数の関数をexportしています。

`qtn_file_*` APIはファイルのQuarantineポリシーを扱い、`qtn_proc_*` APIはプロセス（そのプロセスによって作成されたファイル）に適用されます。非exportの`__qtn_syscall_quarantine*`関数は、ポリシーを適用する関数であり、第一引数に"Quarantine"を指定して`mac_syscall`を呼び出し、リクエストを`Quarantine.kext`に送信します。

#### **Quarantine.kext**

このkernel extensionは**システム上のkernel cacheからのみ**利用できます。ただし、[**https://developer.apple.com/**](https://developer.apple.com/) から**Kernel Debug Kitをダウンロード**できます。これには、symbolicate済みのextensionが含まれています。

このKextはMACFを介して複数の呼び出しをhookし、ファイルのライフサイクルイベント（作成、open、rename、hard-linkningなど）をすべてtrapします。`com.apple.quarantine`拡張属性の設定を防ぐため、`setxattr`さえもtrapします。

また、いくつかのMIBを使用します。

- `security.mac.qtn.sandbox_enforce`: SandboxとともにQuarantineを強制する
- `security.mac.qtn.user_approved_exec`: Querantinedプロセスは承認済みファイルのみ実行できる

#### Provenance xattr（Ventura以降）

macOS 13 Venturaでは、Quarantineされたアプリの実行が初めて許可されたときに生成される、独立したprovenance mechanismが導入されました。<sup>[[2]](#references)</sup> 2つのartefactが作成されます。

- `.app` bundleディレクトリにある`com.apple.provenance` xattr（primary keyとflagsを含む固定サイズのbinary値）。
- `/var/db/SystemPolicyConfiguration/ExecPolicy/`のExecPolicy database内にある`provenance_tracking`テーブルのrow。アプリのcdhashとmetadataが保存されます。

実用的な使用例：
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtectは、macOSに組み込まれた**anti-malware**機能です。XProtectは、**アプリケーションが初めて起動されたとき、または変更されたときに、既知のマルウェアや安全でないファイルタイプのデータベースと照合します**。Safari、Mail、Messagesなどの特定のアプリを通じてファイルをダウンロードすると、XProtectはファイルを自動的にスキャンします。データベース内の既知のマルウェアと一致した場合、XProtectは**ファイルの実行を防止し**、脅威について警告します。

XProtectのデータベースは、Appleによって新しいマルウェア定義で**定期的に更新**され、これらの更新はMacに自動的にダウンロードおよびインストールされます。これにより、XProtectは最新の既知の脅威に常に対応できます。

ただし、**XProtectはフル機能のアンチウイルスソリューションではありません**。特定の既知の脅威リストのみをチェックし、ほとんどのアンチウイルスソフトウェアのようなon-access scanningは実行しません。

次のコマンドを実行すると、最新のXProtectアップデートに関する情報を取得できます：
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect は SIP で保護された **/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあります。バンドル内には、XProtect が使用する以下の情報があります。

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらの cdhash を持つコードに、legacy entitlements の使用を許可します。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID と TeamID によってロードを禁止するプラグインおよび拡張機能、または最低バージョンを示す一覧です。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware を検出するための Yara ルールです。
- **`XProtect.bundle/Contents/Resources/gk.db`**: ブロックされたアプリケーションと TeamID のハッシュを含む SQLite3 データベースです。

**`/Library/Apple/System/Library/CoreServices/XProtect.app`** にも XProtect に関連する別の App がありますが、Gatekeeper のプロセスには関与していません。

> XProtect Remediator: modern macOS では、Apple は malware のファミリーを検出および remediation するため、launchd 経由で定期的に実行される on-demand scanner（XProtect Remediator）を提供しています。これらのスキャンは unified logs で確認できます。
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper ではないもの

> [!CAUTION]
> Gatekeeper はアプリケーションを実行するたびに実行されるわけではありません。_**AppleMobileFileIntegrity**_ が、Gatekeeper によってすでに実行および検証されたアプリを実行するときに、**executable code signatures** のみを検証します。

そのため以前は、Gatekeeper でアプリを cache するために実行し、その後アプリケーションの **executable ではないファイル**（Electron の asar や NIB ファイルなど）を**変更**できました。他の保護がなければ、アプリケーションはその**悪意のある**追加要素とともに**実行**されました。

しかし現在は、macOS がアプリケーションバンドル内のファイルの**変更を防止**するため、これは不可能です。したがって、[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack を試みると、Gatekeeper で cache するためにアプリを実行した後はバンドルを変更できないため、もはや悪用できないことが分かります。また、exploit で示されているように、たとえば Contents ディレクトリの名前を NotCon に変更してから、Gatekeeper で cache するためにアプリの main binary を実行すると、エラーが発生して実行されません。

## Gatekeeper Bypasses

Gatekeeper を bypass する方法（Gatekeeper が disallow すべきものをユーザーに download および execute させること）は、macOS の vulnerability とみなされます。過去に Gatekeeper の bypass を可能にした technique に割り当てられた CVE は以下のとおりです。

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility** を extraction に使用した場合、**886 文字を超えるパス**を持つファイルには com.apple.quarantine extended attribute が付与されないことが確認されました。この状況により、それらのファイルは意図せず **Gatekeeper の** security checks を**回避**できます。<sup>[[5]](#references)</sup>

詳細については[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を確認してください。<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator** でアプリケーションを作成すると、実行に必要な情報は executable ではなく `application.app/Contents/document.wflow` 内にあります。executable は、**Automator Application Stub** と呼ばれる汎用の Automator binary にすぎません。

そのため、`application.app/Contents/MacOS/Automator\ Application\ Stub` を**システム内の別の Automator Application Stub への symbolic link にする**ことができ、実際の executable には quarantine xattr がないため、**Gatekeeper を trigger せずに** `document.wflow`（あなたの script）内の内容を実行できます。<sup>[[6]](#references)</sup>

想定される場所の例: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を確認してください。<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

この bypass では、`application.app` ではなく `application.app/Contents` から compress を開始するアプリケーションを含む zip file が作成されました。そのため、**quarantine attr** は **`application.app/Contents` 内のすべてのファイル**には適用されましたが、Gatekeeper が check していた **`application.app`** には適用されませんでした。その結果、`application.app` が trigger されたときに**quarantine attribute がなかった**ため、Gatekeeper が bypass されました。<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)を確認してください。<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントは異なりますが、この脆弱性の exploitation は前述のものと非常によく似ています。この場合、**`application.app/Contents`** から Apple Archive を生成するため、**`application.app`** は **Archive Utility** によって展開された際に quarantine attr を取得しません。<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
詳細については、[**原文レポート**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)を確認してください。<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**を使用すると、誰もファイル内の属性を書き込めないようにできます：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
さらに、**AppleDouble** ファイル形式では、ファイルがその ACE とともにコピーされます。<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) では、**`com.apple.acl.text`** という xattr 内に保存された ACL のテキスト表現が、展開されたファイルの ACL として設定されることを確認できます。したがって、他の xattr が書き込まれるのを防ぐ ACL を設定した **AppleDouble** ファイル形式でアプリケーションを zip ファイルに圧縮すると... quarantine xattr はアプリケーションに設定されませんでした：
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。<sup>[[9]](#references)</sup>

これは AppleArchives を使用しても exploit できることに注意してください:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chrome がダウンロードしたファイルに quarantine attribute を設定していなかった**ことが、macOS の内部的な問題により判明しました。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble は、ファイル名が `._` で始まる別のファイルにファイルの属性を保存します。これは、ファイル属性を**macOS マシン間で**コピーするのに役立ちます。しかし、AppleDouble ファイルを解凍した後、`._` で始まるファイルに**quarantine attribute が付与されていませんでした**。<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
quarantine attribute が設定されないファイルを作成できたため、**Gatekeeper を bypass することが可能でした。** その手法は、AppleDouble の命名規則（`._` で始める）を使用して **DMG file application** を作成し、quarantine attribute のないこの hidden file への **visible file を sym link として作成する**というものでした。\
**dmg file を実行すると**、quarantine attribute がないため、**Gatekeeper を bypass します。**
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

macOS Sonoma 14.0で修正されたGatekeeper bypassにより、細工されたアプリをプロンプトなしで実行できました。詳細はパッチ適用後に公開され、この問題は修正前に実際の環境で積極的に悪用されていました。Sonoma 14.0以降がインストールされていることを確認してください。<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4（2024年3月リリース）におけるGatekeeper bypassは、悪意のあるZIPの`libarchive`による処理に起因し、アプリがassessmentを回避できるものでした。Appleがこの問題に対処した14.4以降へアップデートしてください。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードしたアプリに埋め込まれた**Automator Quick Action workflow**が、Gatekeeperのassessmentなしでトリガーされる可能性がありました。これは、workflowがデータとして扱われ、通常のnotarization promptの経路外でAutomator helperによって実行されていたためです。そのため、shell scriptを実行するQuick Action（例：`Contents/PlugIns/*.workflow/Contents/document.wflow`内）をバンドルした細工済みの`.app`は、起動時に直ちに実行される可能性がありました。Appleは追加の同意ダイアログを追加し、Ventura **13.7**、Sonoma **14.7**、Sequoia **15**でassessmentの経路を修正しました。<sup>[[3]](#references)</sup>

### サードパーティ製unarchiverによるquarantineの誤った伝播（2023–2024）

複数の一般的なextraction tool（例：The Unarchiver）の脆弱性により、アーカイブからextractされたファイルに`com.apple.quarantine` xattrが付与されず、Gatekeeper bypassの機会が生じていました。テスト時は必ずmacOS Archive Utilityまたはパッチ適用済みのtoolを使用し、extract後にxattrを検証してください。

### uchg（この[講演](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)より）

- アプリを含むディレクトリを作成します。
- アプリにuchgを追加します。
- アプリをtar.gzファイルに圧縮します。
- tar.gzファイルを被害者に送信します。
- 被害者がtar.gzファイルを開き、アプリを実行します。
- Gatekeeperはアプリをチェックしません。<sup>[[12]](#references)</sup>

### Quarantine xattrを防止する

".app"バンドルにquarantine xattrが追加されていない場合、それを実行しても**Gatekeeperはトリガーされません**。

## References

- [1] [Apple Platform Security：macOS Sonoma 14.4のセキュリティコンテンツについて（CVE-2024-27853を含む）](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light：macOSがアプリのprovenanceを追跡するようになった方法](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple：macOS Sonoma 14.7 / Ventura 13.7のセキュリティコンテンツについて（CVE-2024-44128）](https://support.apple.com/en-us/121234)
- [4] [MacRumors：macOS 15 SequoiaがControl-clickによる「Open」Gatekeeper bypassを削除](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs：CVE-2021-1810の発見](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990、macOS Gatekeeperのbypass](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat LabsがGatekeeper bypassを可能にするSafari vulnerabilityを特定](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat LabsがGatekeeper bypassを可能にするmacOS Archive Utility vulnerability（CVE-2022-32910）を特定](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [GatekeeperのAchilles heel：macOS vulnerabilityを発掘](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure：Gatekeeper Bypass（CVE-2023-27943）の発見](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitorの支援によるGatekeeper bypass exploitの発見と報告](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023：macOS Security and Privacy Mechanismsのbypass — GatekeeperからSystem Integrity Protectionまで（Koh Nakagawa）](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple：macOS Sonoma 14のセキュリティコンテンツについて（CVE-2023-41067）](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
